rule openssh_portable
{
    meta:
        description = "Detection patterns for the tool 'openssh-portable' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "openssh-portable"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\\\\pipe\\\\openssh\-ssh\-agent/ nocase ascii wide
                        $string2 = /\\OpenSSHTestTasks\\/ nocase ascii wide
                        $string3 = /\\pipe\\openssh\-ssh\-agent/ nocase ascii wide
                        $string4 = /\\Software\\OpenSSH\\DefaultShell/ nocase ascii wide
                        $string5 = /install\-sshd\.ps1/ nocase ascii wide
                        $string6 = "net start ssh-agent" nocase ascii wide
                        $string7 = "New-Service -Name sshd" nocase ascii wide

    condition:
        any of them
}