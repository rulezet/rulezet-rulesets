rule fakelogonscreen
{
    meta:
        description = "Detection patterns for the tool 'fakelogonscreen' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "fakelogonscreen"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/fakelogonscreen\.exe/ nocase ascii wide
                        $string2 = /\/fakelogonscreen\.git/ nocase ascii wide
                        $string3 = "/fakelogonscreen/releases/download/" nocase ascii wide
                        $string4 = "/fakelogonscreen/tarball/" nocase ascii wide
                        $string5 = "/fakelogonscreen/zipball/" nocase ascii wide
                        $string6 = /\\FakeLogonScreen\.exe/ nocase ascii wide
                        $string7 = /\\FakeLogonScreen\.sln/ nocase ascii wide
                        $string8 = /\\fakelogonscreen\-master/ nocase ascii wide
                        $string9 = "361ec6983d4a8683b685dc4f9b7280e4faebf3a4006cc44c7aab3ea94fe9d2d4" nocase ascii wide
                        $string10 = "3c39207a61a348efa7dd2db2d85c1e562beedfa8c4593d1d29b7751bc84aad85" nocase ascii wide
                        $string11 = "5042151210128f823c5cc143d52c6df18ea3bab1f834f7613d57600a6afc543e" nocase ascii wide
                        $string12 = "532a1b17840d0746c48f98d0f24443bd60111db4f3c5f82872ec5e4e6854438a" nocase ascii wide
                        $string13 = "7fef9543926764b6093a5ab10ea9d092f9a97acae14dbfd423a7c52cc9454fdb" nocase ascii wide
                        $string14 = "81e1e9186bb461b669b4bbd4dab4534c980e6d2bc27975e6ec7305bc935cf429" nocase ascii wide
                        $string15 = "88dc61a50afafe0e0ffff60913d45f2abe2a298c2c8a067fc7044e7251eb9012" nocase ascii wide
                        $string16 = "98d590b2d7e7ee6c87e251a26f155e9c20765829e8ac291092d139aaa6fae676" nocase ascii wide
                        $string17 = "bitsadmin/fakelogonscreen" nocase ascii wide
                        $string18 = "D35A55BD-3189-498B-B72F-DC798172E505" nocase ascii wide
                        $string19 = "e3a0aa509ad07aab04f9a052a9abc681d414871cd0277deef4b95ea98f1243c8" nocase ascii wide
                        $string20 = /fakelogonscreen.{0,1000}\.zip/ nocase ascii wide
                        $string21 = /FakeLogonScreen\.csproj/ nocase ascii wide
                        $string22 = /FakeLogonScreen\.Properties\.Resources/ nocase ascii wide
                        $string23 = /FakeLogonScreen_trunk\.zip/ nocase ascii wide
                        $string24 = /FakeLogonScreenToFile\.exe/ nocase ascii wide

    condition:
        any of them
}