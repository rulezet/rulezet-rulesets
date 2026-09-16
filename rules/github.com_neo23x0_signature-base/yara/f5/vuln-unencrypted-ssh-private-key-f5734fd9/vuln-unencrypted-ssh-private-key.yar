rule VULN_Unencrypted_SSH_Private_Key : T1552_004 {
    meta:
        description = "Detects unencrypted SSH private keys with DSA, RSA, ECDSA and ED25519 of openssh or Putty"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp"
        date = "2023-01-06"
        reference = "https://attack.mitre.org/techniques/T1552/004/"
        score = 50
        id = "84b279fc-99c8-5101-b2d8-5c7adbaf753f"
    strings:
        
        $openssh_rsa = { 2d 2d 2d 2d 2d 42 45 47 49 4e 20 52 53 41 20 50 52 49 56 41 54 45 20 4b 45 59 2d 2d 2d 2d 2d 0a 4d 49 49 }

        
        $openssh_dsa = { 2d 2d 2d 2d 2d 42 45 47 49 4e 20 44 53 41 20 50 52 49 56 41 54 45 20 4b 45 59 2d 2d 2d 2d 2d 0a 4d 49 49 42 76 41 49 42 41 41 4b 42 67 51 }

        
        $openssh_ecdsa = { 2d 2d 2d 2d 2d 42 45 47 49 4e 20 45 43 20 50 52 49 56 41 54 45 20 4b 45 59 2d 2d 2d 2d 2d 0a 4d }

        
        $openssh_ed25519 = { 2d 2d 2d 2d 2d 42 45 47 49 4e 20 4f 50 45 4e 53 53 48 20 50 52 49 56 41 54 45 20 4b 45 59 2d 2d 2d 2d 2d 0a 62 33 42 6c 62 6e 4e 7a 61 43 31 72 5a 58 6b 74 64 6a 45 41 41 41 41 41 42 47 35 76 62 6d 55 }

        $putty_start = "PuTTY-User-Key-File" ascii
        $putty_noenc = "Encryption: none" ascii

    condition:
        
        (
            filepath contains "ssh" or
            filepath contains "SSH" or
            filepath contains "utty" or
            filename contains "ssh" or
            filename contains "SSH" or
            filename contains "id_" or
            filename contains "id2_" or
            filename contains ".ppk" or
            filename contains ".PPK" or
            filename contains "utty"
        )
        and
        (
            $openssh_dsa     at 0 or
            $openssh_rsa     at 0 or
            $openssh_ecdsa   at 0 or
            $openssh_ed25519 at 0 or
            (
                $putty_start at 0 and
                $putty_noenc
            )
        )
        and not filepath contains "/root/"
        and not filename contains "ssh_host_"
}