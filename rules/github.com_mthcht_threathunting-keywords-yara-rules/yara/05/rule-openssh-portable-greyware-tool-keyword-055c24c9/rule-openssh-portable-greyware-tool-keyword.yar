rule rule_openssh_portable_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'openssh-portable' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "openssh-portable"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_openssh_portable_greyware_tool_keyword = /\\\\pipe\\\\openssh\-ssh\-agent/ nocase ascii wide
                        $string2_openssh_portable_greyware_tool_keyword = /\\OpenSSHTestTasks\\/ nocase ascii wide
                        $string3_openssh_portable_greyware_tool_keyword = /\\pipe\\openssh\-ssh\-agent/ nocase ascii wide
                        $string4_openssh_portable_greyware_tool_keyword = /\\Software\\OpenSSH\\DefaultShell/ nocase ascii wide
                        $string5_openssh_portable_greyware_tool_keyword = /install\-sshd\.ps1/ nocase ascii wide
                        $string6_openssh_portable_greyware_tool_keyword = "net start ssh-agent" nocase ascii wide
                        $string7_openssh_portable_greyware_tool_keyword = "New-Service -Name sshd" nocase ascii wide

    condition:
        any of them
}