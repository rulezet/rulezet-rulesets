import "pe"
rule _Virus_Hijack_Gen_Trojan_ShellObject_iuZ_amBwvTb_1_2_Virus_Hijac_47 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.iuZ@amBwvTb_1_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.k8W@aKuHmDp_10_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.MuZ@amBwvTb_26_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7675e664ca1e9b3ebf3a7b2e3d1433ad4b7a66c34cc8ef17ca865ea19b36d48e"
    hash2       = "30b223ce803ec0ed8ae732f7eb2d644b2525d139a82a88206bba1ae65b3644b9"
    hash3       = "24d19ef1d07bc82d47ef275b0a510b037eb886f2a780894325c766915dcff7dc"

  strings:
    $s1  = "Executing command: %s with%spty" fullword ascii
    $s2  = "%s: type mismatch for decoded key (received %d, expected %d)" fullword ascii
    $s3  = "failed to generate sshd user temporary password" fullword ascii
    $s4  = "Read error from remote host %.100s port %d: %.100s" fullword ascii
    $s5  = "%s line %d: missing AuthorizedKeysCommandUser argument." fullword ascii
    $s6  = "%s: originator %s port %d, target %s" fullword ascii
    $s7  = "%s: originator %s port %d, target %s port %d" fullword ascii
    $s8  = "Attempt to write login records by non-root user (aborting)" fullword ascii
    $s9  = "%s: %s command \"%s\" running as %s (flags 0x%x)" fullword ascii
    $s10 = "%.200s line %d: AuthorizedPrincipalsCommand must be an absolute path" fullword ascii
    $s11 = "%s line %d: missing AuthorizedPrincipalsCommandUser argument." fullword ascii
    $s12 = "%s line %d: invalid DenyUsers pattern: \"%.100s\"" fullword ascii
    $s13 = "%s: key type %s not in HostbasedAcceptedKeyTypes" fullword ascii
    $s14 = "%s: %s:%ld: bad host hash \"%.32s\"" fullword ascii
    $s15 = "%s: couldn't put hostkey %d: %s" fullword ascii
    $s16 = "%s: GetTokenInformation() failed with error %d" fullword ascii
    $s17 = "%s: %s key not permitted by HostkeyAlgorithms" fullword ascii
    $s18 = "%s: unknown host %s key" fullword ascii
    $s19 = "%s: root user, ignoring system hosts files" fullword ascii
    $s20 = "%s line %d: invalid AllowUsers pattern: \"%.100s\"" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "27de371e1dae125bc04cc09552c72d87" and (8 of them)
    ) or (all of them)
}