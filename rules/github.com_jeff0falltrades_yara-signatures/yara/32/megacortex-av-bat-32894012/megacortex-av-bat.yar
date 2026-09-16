rule megacortex_av_bat {
    meta:
        author = "jeFF0Falltrades"

    strings:
        $str_1 = "taskkill /IM agntsvc.exe /Ftaskkill /IM dbeng50.exe /F"
        $str_2 = "net stop SQLAgent$SOPHOS /ynet stop AVP /y"
        $str_3 = "net stop \"Sophos Clean Service\" /y"
        $str_4 = "net stop \"Sophos Device Control Service\" /y"
        $str_5 = "net stop \"Sophos File Scanner Service\" /y"
        $str_6 = "net stop \"Sophos Health Service\" /y"
        $str_7 = "net stop \"Sophos MCS Agent\" /y"
        $str_8 = "net stop \"Sophos MCS Client\" /y"
        $str_9 = "net stop \"Sophos Message Router\" /y"
        $str_10 = "net stop \"Sophos Safestore Service\" /y"
        $str_11 = "net stop \"Sophos System Protection Service\" /y"
        $str_12 = "net stop \"Sophos Web Control Service\" /y"
        $str_13 = "sc config VeeamHvIntegrationSvc start= disabled"
        $str_14 = "sc config MSSQL$VEEAMSQL2012 start"
        $str_15 = "sc config SQLAgent$CXDB start= disabled"
        $str_16 = "taskkill /IM zoolz.exe /F"
        $str_17 = "taskkill /IM agntsvc.exe /Ftaskkill /IM dbeng50.exe /F"
        $str_18 = "taskkill /IM wordpad.exe /F"
        $str_19 = "taskkill /IM xfssvccon.exe /F"
        $str_20 = "taskkill /IM tmlisten.exe /F"
        $str_21 = "taskkill /IM PccNTMon.exe /F"
        $str_22 = "taskkill /IM CNTAoSMgr.exe /F"
        $str_23 = "taskkill /IM Ntrtscan.exe /F"
        $str_24 = "taskkill /IM mbamtray.exe /F"
        $str_25 = "iisreset /stop"

    condition:
        5 of them
}