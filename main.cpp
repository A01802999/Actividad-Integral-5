/*
    ============================================================
    Actividad Integral 5 - Códigos Hash y Detección de DDoS
    Valeria Portilla Robles (A01752371)
    Alexa Ávila Luna (A01803526)
    Diego Sánchez Mancilla (A01802999)
    Descripción general:
        Programa que identifica accesos cercanos a dominios destino
        dentro de una ventana de 30 segundos, usando un mapa hash.
    ============================================================
*/

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <unordered_map>
#include <algorithm>
#include <ctime>
using namespace std;

struct Ip {
    int o1, o2, o3, o4;   // octetos de la IP
};

struct Event {
    tm ts{};              // fecha y hora
    Ip ipO{};             // IP de origen
    string portO, domainO;
    Ip ipD{};             // IP de destino
    string portD, domainD;
};

Ip parseIp(const string &s) {
    if (s == "-") return {0,0,0,0};   // caso sin IP
    Ip out{};
    char dot;
    istringstream ss(s);
    ss >> out.o1 >> dot >> out.o2 >> dot >> out.o3 >> dot >> out.o4; // separar octetos
    return out;
}

tm parseDateTime(const string &dateS, const string &timeS) {
    tm t{};
    int d, m, y;
    char dash;

    istringstream ds(dateS);
    ds >> d >> dash >> m >> dash >> y;     // separar fecha

    int hh, mm, ss;
    char colon;
    istringstream ts(timeS);
    ts >> hh >> colon >> mm >> colon >> ss; // separar hora

    t.tm_year = y - 1900;   // ajustar año
    t.tm_mon  = m - 1;      // ajustar mes
    t.tm_mday = d;          // día
    t.tm_hour = hh;         // hora
    t.tm_min  = mm;         // minuto
    t.tm_sec  = ss;         // segundo

    return t;
}

bool parseEvent(const string &line, Event &e) {
    istringstream ss(line);
    string dateS, timeS, ipOS, portOS, domOS, ipDS, portDS, domDS;

    if (!getline(ss, dateS, ',')) return false;   // leer fecha
    if (!getline(ss, timeS, ',')) return false;   // leer hora
    if (!getline(ss, ipOS, ',')) return false;    // IP origen
    if (!getline(ss, portOS, ',')) return false;  // puerto origen
    if (!getline(ss, domOS, ',')) return false;   // dominio origen
    if (!getline(ss, ipDS, ',')) return false;    // IP destino
    if (!getline(ss, portDS, ',')) return false;  // puerto destino
    if (!getline(ss, domDS)) return false;        // dominio destino

    e.ts      = parseDateTime(dateS, timeS);  // convertir timestamp
    e.ipO     = parseIp(ipOS);                // convertir IP origen
    e.portO   = portOS;
    e.domainO = domOS;
    e.ipD     = parseIp(ipDS);                // convertir IP destino
    e.portD   = portDS;
    e.domainD = domDS;

    return true;
}

bool operator<(const Event &a, const Event &b) {
    return mktime(const_cast<tm*>(&a.ts)) < mktime(const_cast<tm*>(&b.ts)); // comparar tiempo
}

int main() {
    ifstream fin("equipo4_sorted.csv");
    if (!fin) {
        cerr << "No se pudo abrir el archivo\n"; 
        return 1;
    }

    vector<Event> logs;
    string line;

    while (getline(fin, line)) {
        if (line.empty()) continue;     // ignorar líneas vacías
        Event e;
        if (parseEvent(line, e))
            logs.push_back(e);          // guardar evento
    }
    fin.close();

    sort(logs.begin(), logs.end());     // asegurar que estén ordenados por tiempo

    unordered_map<string, pair<time_t,int>> mp;  // dominio → {último acceso, contador}

    for (const auto &e : logs) {
        time_t current = mktime(const_cast<tm*>(&e.ts)); // timestamp actual

        if (!mp.count(e.domainD)) {        // primera vez que aparece
            mp[e.domainD] = {current, 0};
        } else {
            time_t last = mp[e.domainD].first;      // último acceso
            double diff = difftime(current, last);  // diferencia en segundos

            if (diff >= 0 && diff <= 30)            // dentro de 30s
                mp[e.domainD].second++;             // sumar acceso cercano

            mp[e.domainD].first = current;          // actualizar último timestamp
        }
    }

    vector<pair<string,int>> ranking;
    for (const auto &p : mp)
        ranking.push_back({p.first, p.second.second});  // dominio y su contador

    sort(ranking.begin(), ranking.end(),
         [](auto &a, auto &b){ return a.second > b.second; }); // ordenar descendente

    cout << "\nTOP 10 dominios con mas accesos cercanos (<30s):\n";
    for (int i = 0; i < 10 && i < ranking.size(); i++) {
        cout << i+1 << ". "
             << ranking[i].first 
             << " -> " 
             << ranking[i].second 
             << " accesos cercanos\n";  // imprimir ranking
    }

    return 0;
}
