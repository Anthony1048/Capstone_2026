#include <iostream>
#include <string>
#include <array>
#include <cstdio>
#include <stdexcept>
#include <fstream>
#include <sstream>
//json parsing library
#include "nlohmann/json.hpp"
//define windows version so httplib targets modern windows APIs
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif

#ifndef WINVER
#define WINVER 0x0A00
#endif
//networking support
#include <winsock2.h>
//windows system functions
#include <windows.h>
//local web server library
#include "httplib.h"

using namespace std;
using json = nlohmann::json;

//store last scan so report button can use it
json g_lastScan;
//tracks if valid scan has completed
bool g_hasScanResults = false;

//runs python scanner command and captures what it prints
string CaptureOutput(const string& command)
{
    array<char, 256> buffer{};
    string output;
    //start scanner and open pipe for output
    FILE* pipe = _popen(command.c_str(), "r");
    if (!pipe)
    {
        throw runtime_error("Failed to start Python scanner.");
    }
    //read scanner output
    while (fgets(buffer.data(), buffer.size(), pipe))
    {
        output += buffer.data();
    }

    _pclose(pipe);
    return output;
}

//save json to file
bool SaveJson(const json& scan, const string& filename)
{
    ofstream out(filename);
    if (!out.is_open())
    {
        return false;
    }
    //writes formated json with indentation
    out << scan.dump(2);
    return true;
}

//read html file into a single string
string ReadFile(const string& filename)
{
    ifstream in(filename);
    if (!in.is_open())
    {
        return "";
    }

    stringstream buffer;
    buffer << in.rdbuf();
    return buffer.str();
}

//build the browser result page from scan data
string BuildResultsPage(const json& scan)
{
    int crit = 0, high = 0, med = 0, low = 0;
    //count findings by severity
    if (scan.contains("findings"))
    {
        for (const auto& f : scan["findings"])
        {
            string s = f.value("severity", "");
            if (s == "Critical") crit++;
            else if (s == "High") high++;
            else if (s == "Medium") med++;
            else if (s == "Low") low++;
        }
    }
    //build html result page as a string
    string html;
    html += "<html><body>";
    html += "<h1>Scan Results</h1>";

    //show severity summary
    html += "<p>Critical: " + to_string(crit) + "</p>";
    html += "<p>High: " + to_string(high) + "</p>";
    html += "<p>Medium: " + to_string(med) + "</p>";
    html += "<p>Low: " + to_string(low) + "</p>";
    //show finding section
    html += "<h2>Security Issues</h2>";
    //if no findings display message
    if (scan["findings"].empty())
    {
        html += "<p>No findings</p>";
        //else display each finding
    }
    else
    {
        for (const auto& f : scan["findings"])
        {
            html += "<hr>";
            html += "<p><b>ID:</b> " + f.value("id", "") + "</p>";
            html += "<p><b>Name:</b> " + f.value("name", "") + "</p>";
            html += "<p><b>Severity:</b> " + f.value("severity", "") + "</p>";
            html += "<p><b>Description:</b> " + f.value("description", "") + "</p>";
        }
    }
    //Updated
    //show security feature status section
    html += "<h2>Security Features Scanned</h2>";
    if (scan.contains("statuses") && !scan["statuses"].empty())
    {
        for (const auto& s : scan["statuses"])
        {
            string status = s.value("status", "");
            string color, icon;
            if (status == "Pass")      { color = "green";  icon = "&#10003;"; }
            else if (status == "Fail") { color = "red";    icon = "&#10007;"; }
            else                       { color = "orange"; icon = "&#9888;"; }
            html += "<p><span style='color:" + color + ";font-weight:bold;'>" + icon + " " + status + "</span>";
            html += " &mdash; <b>" + s.value("name", "") + "</b>: " + s.value("description", "") + "</p>";
        }
    }
    else
    {
        html += "<p>No status data available.</p>";
    }//Updated
    //run scan again button
    html += "<br><form method='post' action='/run-scan'>";
    html += "<button>Run Scan Again</button></form>";
    //generate report button
    html += "<br><form method='post' action='/generate-report'>";
    html += "<button>Generate Report</button></form>";
    //exit button
    html += "<br><form method='post' action='/exit'>";
    html += "<button>Exit</button></form>";

    html += "</body></html>";

    return html;
}

int main()
{
    //create local webserver object
    httplib::Server server;
    //Updated
    //homepage, when browser requests "/", return index.html
    server.Get("/", [](const httplib::Request&, httplib::Response& res)
    {
        res.set_content(ReadFile("html/index.html"), "text/html");
    });

    //serve stylesheet
    server.Get("/style.css", [](const httplib::Request&, httplib::Response& res)
    {
        res.set_content(ReadFile("html/style.css"), "text/css");
    });

    //run scan route, when the browser posts to /run-scan, the scanner executes
    server.Post("/run-scan", [](const httplib::Request&, httplib::Response& res)
    {
        try
        {
            //run python scanner and capture its output
            string output = CaptureOutput("py python/scanner.py");

            //strip everything before JSON starts
            size_t jsonStart = output.find('{');
            if (jsonStart != string::npos)
            {
                output = output.substr(jsonStart);
            }

            // handling if scanner prints nothing
            if (output.empty())
            {
                res.set_content("<h1>Error: No output</h1>", "text/html");
                return;
            }
            //Updated
            //parse scanner output into json
            json scan = json::parse(output);
            //save last scan in memory
            g_lastScan = scan;
            g_hasScanResults = true;
            //return results page to browser
            res.set_content(BuildResultsPage(scan), "text/html");
        }
        //return error page if anything goes wrong
        catch (exception& ex)
        {
            string err = "<h1>Error</h1><p>" + string(ex.what()) + "</p>";
            res.set_content(err, "text/html");
        }
    });
    //exit route, when browser posts to /exit, stop the local server
    server.Post("/exit", [&](const httplib::Request&, httplib::Response& res)
    {
        //display closing message
        res.set_content("<h1>Application closed</h1>", "text/html");
        //stop server
        server.stop();
    });
    //generate report, when the browser posts to /generate-report, build final_report.html
    server.Post("/generate-report", [](const httplib::Request&, httplib::Response& res)
    {
        //save latest scan json to report.json
        if (!SaveJson(g_lastScan, "generated reports/report.json"))
        {
            res.set_content("<h1>Failed to save JSON</h1>", "text/html");
            return;
        }
        //run py report generator
        int result = system("py python/report_generator.py \"generated reports/report.json\" html/Capstone.html \"generated reports/final_report.html\"");
        //if it works, generate report else report an error
        if (result == 0)
        {
            system("start \"\" \"generated reports\\final_report.html\"");
            //return user to results page so app can still be used
            res.set_content(BuildResultsPage(g_lastScan), "text/html");
        }
        else
        {
            res.set_content("<h1>Report failed</h1>", "text/html");
        }
    });

    //automatically open the browser to the local UI
    system("start http://127.0.0.1:8080");
    //start listening on localhost port 8080
    server.listen("127.0.0.1", 8080);

    return 0;
}
