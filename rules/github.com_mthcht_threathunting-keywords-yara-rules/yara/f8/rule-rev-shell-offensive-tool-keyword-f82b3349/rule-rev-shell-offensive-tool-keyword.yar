rule rule_Rev_Shell_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Rev-Shell' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Rev-Shell"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Rev_Shell_offensive_tool_keyword = /\srevshell\.py/ nocase ascii wide
                        $string2_Rev_Shell_offensive_tool_keyword = /\\"Generate\sreverse\sshell\spayloads\.\\"/ nocase ascii wide
                        $string3_Rev_Shell_offensive_tool_keyword = /\/Rev\-Shell\.git/ nocase ascii wide
                        $string4_Rev_Shell_offensive_tool_keyword = /\/revshell\.py/ nocase ascii wide
                        $string5_Rev_Shell_offensive_tool_keyword = /\\nGenerated\spayload\:/ nocase ascii wide
                        $string6_Rev_Shell_offensive_tool_keyword = /\\revshell\.py/ nocase ascii wide
                        $string7_Rev_Shell_offensive_tool_keyword = /\|\/bin\/sh\s\-i\s2\>\&1\|nc\s.{0,100}\s\>\/tmp\/f/
                        $string8_Rev_Shell_offensive_tool_keyword = "a280f960cb4fc01ec2dbb4fe56f17122523878a9ece3713868244fbd95e7d7e6" nocase ascii wide
                        $string9_Rev_Shell_offensive_tool_keyword = /bash\s\-i\s\&\>\/dev\/tcp\/.{0,100}\s\<\&1/
                        $string10_Rev_Shell_offensive_tool_keyword = /generate_payload\(language\,\sip\,\sport\)/ nocase ascii wide
                        $string11_Rev_Shell_offensive_tool_keyword = /nc\s\-e\s\/bin\/sh\s.{0,100}\s/
                        $string12_Rev_Shell_offensive_tool_keyword = /powershell\s\-c\s.{0,100}New\-Object\sSystem\.Net\.Sockets\.TCPClient\(\\".{0,100}\$sendback\s\=\s\(iex\s.{0,100}\$data.{0,100}\s2\>\&1\s\|\sOut\-String/ nocase ascii wide
                        $string13_Rev_Shell_offensive_tool_keyword = /s\=socket\.socket\(socket\.AF_INET\,socket\.SOCK_STREAM\)\;s\.connect\(.{0,100}os\.dup2\(s\.fileno.{0,100}pty\.spawn\(\\"\/bin\/bash/
                        $string14_Rev_Shell_offensive_tool_keyword = /TF\=.{0,100}mkfifo\s.{0,100}\s\&\&\stelnet\s.{0,100}\s0\<.{0,100}\|\s\/bin\/sh\s1\>/
                        $string15_Rev_Shell_offensive_tool_keyword = "washingtonP1974/Rev-Shell" nocase ascii wide
                        $string16_Rev_Shell_offensive_tool_keyword = /www\.revshells\.com/ nocase ascii wide
        $metadata_regex_import = /\bimport\s+[a-zA-Z0-9_.]+\b/ nocase
        $metadata_regex_function = /function\s+[a-zA-Z_][a-zA-Z0-9_]*\(/ nocase ascii
        $metadata_regex_php = /<\?php/ nocase ascii
        $metadata_regex_createobject = /(CreateObject|WScript\.)/ nocase ascii
        $metadata_regex_script = /<script\b/ nocase ascii
        $metadata_regex_javascript = /(let\s|const\s|function\s|document\.|console\.)/ nocase ascii
        $metadata_regex_powershell = /(Write-Host|Get-[a-zA-Z]+|Invoke-|param\(|\.SYNOPSIS)/ nocase ascii
        $metadata_regex_batch = /@(echo\s|call\s|set\s|goto\s|if\s|for\s|rem\s)/ nocase ascii
        $metadata_regex_shebang = /^#!\// nocase ascii

    condition:
        ((filesize < 20MB and (
            uint16(0) == 0x5a4d or             uint16(0) == 0x457f or             uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or             uint32(0) == 0x504B0304 or             uint32(0) == 0xCAFEBABE or             uint32(0) == 0x4D534346 or             uint32(0) == 0xD0CF11E0 or             uint16(0) == 0x2321 or             uint16(0) == 0x3c3f         )) and any of ($string*)) or
        (filesize < 2MB and
        (
            any of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}