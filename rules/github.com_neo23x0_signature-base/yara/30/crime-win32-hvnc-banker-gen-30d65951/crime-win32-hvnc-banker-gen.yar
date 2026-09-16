import "pe"
rule crime_win32_hvnc_banker_gen {
    meta:
        description = "Detects malware banker hidden VNC"
        author = "@VK_Intel"
        reference = "https://twitter.com/VK_Intel/status/1247058432223477760"
        date = "2020-04-06"
        id = "5e13f4a9-2231-524f-82b2-fbc6d6a43b6f"
    condition:
        pe.exports("VncStartServer") and pe.exports("VncStopServer")
}