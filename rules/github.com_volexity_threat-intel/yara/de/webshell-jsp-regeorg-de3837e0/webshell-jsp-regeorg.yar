rule webshell_jsp_reGeorg
{
    meta:
        author = "threatintel@volexity.com"
        description = "Detects the reGeorg webshells' JSP version."
        date = "2022-03-08"
        hash1 = "f9b20324f4239a8c82042d8207e35776d6777b6305974964cd9ccc09d431b845"
        os = "win"
        os_arch = "all"
        reference = "https://github.com/SecWiki/WebShell-2/blob/master/reGeorg-master/tunnel.jsp"
        scan_context = "file,memory"
        severity = "critical"
        last_modified = "2024-09-20T10:44:33Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 6575
        version = 5

    strings:
        $magic = "socketChannel.connect(new InetSocketAddress(target, port))" ascii

        $a1 = ".connect(new InetSocketAddress" ascii
        $a2 = ".configureBlocking(false)" ascii
        $a3 = ".setHeader(" ascii
        $a4 = ".getHeader(" ascii
        $a5 = ".flip();" ascii

    condition:
        $magic or
        all of ($a*)
}