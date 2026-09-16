rule APT_MAL_CN_Wocao_webshell_webinfo {
    meta:
        description = "Generic strings from webinfo.war webshells"
        author = "Fox-IT SRT"
        reference = "https://www.fox-it.com/en/news/whitepapers/operation-wocao-shining-a-light-on-one-of-chinas-hidden-hacking-groups/"

        id = "b8477f62-f3f6-5526-b0e3-9b794fefaa1f"
    strings:
        $var1 = "String strLogo = request.getParameter"
        $var2 = "String content = request.getParameter(\"content\");"
        $var3 = "String basePath=request.getScheme()"
        $var4 = "!strLogo.equals("
        $var5 = "if(path!=null && !path.equals(\"\") && content!=null"
        $var6 = "File newfile=new File(path);"

        $str1 = "Save Success!"
        $str2 = "Save Failed!"

    condition:
        2 of ($var*) or (all of ($str*) and 1 of ($var*))
}