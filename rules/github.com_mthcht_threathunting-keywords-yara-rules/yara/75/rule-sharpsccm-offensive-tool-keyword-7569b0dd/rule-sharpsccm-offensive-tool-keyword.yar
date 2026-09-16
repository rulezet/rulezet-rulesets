rule rule_SharpSCCM_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SharpSCCM' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpSCCM"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SharpSCCM_offensive_tool_keyword = " get class-instances SMS_R_System " nocase ascii wide
                        $string2_SharpSCCM_offensive_tool_keyword = " get class-properties SMS_Admin" nocase ascii wide
                        $string3_SharpSCCM_offensive_tool_keyword = " get collection-members -n USERS" nocase ascii wide
                        $string4_SharpSCCM_offensive_tool_keyword = " get primary-users -u " nocase ascii wide
                        $string5_SharpSCCM_offensive_tool_keyword = " get site-push-settings" nocase ascii wide
                        $string6_SharpSCCM_offensive_tool_keyword = " invoke admin-service -q " nocase ascii wide
                        $string7_SharpSCCM_offensive_tool_keyword = " invoke admin-service -q " nocase ascii wide
                        $string8_SharpSCCM_offensive_tool_keyword = /\sinvoke\squery\s.{0,1000}FROM\sSMS_Admin/ nocase ascii wide
                        $string9_SharpSCCM_offensive_tool_keyword = " local class-instances SMS_Authority" nocase ascii wide
                        $string10_SharpSCCM_offensive_tool_keyword = " local class-properties SMS_Authority" nocase ascii wide
                        $string11_SharpSCCM_offensive_tool_keyword = /\slocal\sgrep\s.{0,1000}ccmsetup\sstarted\s.{0,1000}ccmsetup\.log/ nocase ascii wide
                        $string12_SharpSCCM_offensive_tool_keyword = /\slocal\squery\s.{0,1000}\sFROM\sSMS_Authority/ nocase ascii wide
                        $string13_SharpSCCM_offensive_tool_keyword = " local secrets -m disk" nocase ascii wide
                        $string14_SharpSCCM_offensive_tool_keyword = " local secrets -m wmi" nocase ascii wide
                        $string15_SharpSCCM_offensive_tool_keyword = " -p LastLogonTimestamp -p LastLogonUserName " nocase ascii wide
                        $string16_SharpSCCM_offensive_tool_keyword = " remove device GUID:001B2EE1-AE95-4146-AE7B-5928F1E4F396" nocase ascii wide
                        $string17_SharpSCCM_offensive_tool_keyword = " to retrieve secrets from machines that were previously SCCM clients" nocase ascii wide
                        $string18_SharpSCCM_offensive_tool_keyword = /\/SharpSCCM\.exe/ nocase ascii wide
                        $string19_SharpSCCM_offensive_tool_keyword = /\/SharpSCCM\.git/ nocase ascii wide
                        $string20_SharpSCCM_offensive_tool_keyword = "/SharpSCCM/releases/download/" nocase ascii wide
                        $string21_SharpSCCM_offensive_tool_keyword = /\[\!\]\sSharpSCCM\smust\sbe\srun\swith\slocal\sadministrator\sprivileges\sto\sretrieve\spolicy\ssecret\sblobs/ nocase ascii wide
                        $string22_SharpSCCM_offensive_tool_keyword = /\\SharpSCCM\.exe/ nocase ascii wide
                        $string23_SharpSCCM_offensive_tool_keyword = /\\SharpSCCM\-main/ nocase ascii wide
                        $string24_SharpSCCM_offensive_tool_keyword = ">SharpSCCM<" nocase ascii wide
                        $string25_SharpSCCM_offensive_tool_keyword = "03652836-898E-4A9F-B781-B7D86E750F60" nocase ascii wide
                        $string26_SharpSCCM_offensive_tool_keyword = "2170a03a337a89bb3b6a02035ae85946815f8643897ded40fc0a2c29e2e5a960" nocase ascii wide
                        $string27_SharpSCCM_offensive_tool_keyword = "3b765fc9d51180b7ff8c93aa1ab9369fdff33f5ec4ebc4c2e913f8355ca12903" nocase ascii wide
                        $string28_SharpSCCM_offensive_tool_keyword = "54fe99f13b593d3acfc583e17d0bfd2e315d0ee20e737610bede18eb173ae864" nocase ascii wide
                        $string29_SharpSCCM_offensive_tool_keyword = /A\sC\#\sutility\sfor\sinteracting\swith\sSCCM\s\(now\sMicrosoft\sEndpoint\sConfiguration\sManager\)\sby\sChris\sThompson\s\(\@_Mayyhem\)/ nocase ascii wide
                        $string30_SharpSCCM_offensive_tool_keyword = "E4D9EF39-0FCE-4573-978B-ABF8DF6AEC23" nocase ascii wide
                        $string31_SharpSCCM_offensive_tool_keyword = "f945696926267701f5b3327ecb4af54169fd24f780db0f4caecf1fe447848007" nocase ascii wide
                        $string32_SharpSCCM_offensive_tool_keyword = "Mayyhem/SharpSCCM" nocase ascii wide
                        $string33_SharpSCCM_offensive_tool_keyword = "SharpSCCM" nocase ascii wide
                        $string34_SharpSCCM_offensive_tool_keyword = /SharpSCCM\.csproj/ nocase ascii wide
                        $string35_SharpSCCM_offensive_tool_keyword = /SharpSCCM\.exe/ nocase ascii wide
                        $string36_SharpSCCM_offensive_tool_keyword = /SharpSCCM_merged\.exe/ nocase ascii wide

    condition:
        any of them
}