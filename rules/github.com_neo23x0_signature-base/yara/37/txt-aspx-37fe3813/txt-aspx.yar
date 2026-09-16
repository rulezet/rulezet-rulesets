rule Txt_aspx {
    meta:
        description = "Chinese Hacktool Set - Webshells - file aspx.jpg"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-14"
        hash = "ce24e277746c317d887139a0d71dd250bfb0ed58"
        id = "e01a7235-5c69-5676-ac5d-c4e4632f31b2"
    strings:
        $s1 = "SQLExec : <asp:DropDownList runat=\"server\" ID=\"FGEy\" AutoPostBack=\"True\" O" ascii
        $s2 = "Process[] p=Process.GetProcesses();" fullword ascii
        $s3 = "Copyright &copy; 2009 Bin" ascii
        $s4 = "<td colspan=\"5\">CmdShell&nbsp;&nbsp;:&nbsp;<input class=\"input\" runat=\"serv" ascii
    condition:
        filesize < 100KB and all of them
}