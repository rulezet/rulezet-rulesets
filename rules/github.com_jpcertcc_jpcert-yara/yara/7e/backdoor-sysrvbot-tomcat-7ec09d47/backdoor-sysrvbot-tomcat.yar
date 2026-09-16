rule backdoor_SysrvBot_tomcat {
    meta:
        description = "downloader used by SysrvBot"
        author = "JPCERT/CC Incident Response Group"
        hash = "1e2d12a65ea0f79ed8aaf5f14700ac1413375fcff7e600762f9ccdc268391f8b"

    strings:
        $s1 = "&echo ----file ROOT good----" ascii
        $s2 = "application.getRealPath(\"tomcat.jsp\").split(\"\\\\\\\\tomcat.jsp\");" ascii
        $s3 = "ldr.sh?tomcat)|bash" ascii

    condition:
        all of them
}