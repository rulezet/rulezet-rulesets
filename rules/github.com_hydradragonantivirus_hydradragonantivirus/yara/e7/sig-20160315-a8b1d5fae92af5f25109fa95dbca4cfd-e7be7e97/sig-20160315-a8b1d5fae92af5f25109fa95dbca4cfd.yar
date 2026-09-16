rule sig_20160315_a8b1d5fae92af5f25109fa95dbca4cfd {
  meta:
    description = "datamaliciousorder - file 20160315_a8b1d5fae92af5f25109fa95dbca4cfd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0cb6d20bfd51a4a6f938e297155f37f4738239b4af08c1c4c1fa059bb5797003"

  strings:
    $s1 = "        return WScript[e](r);" fullword ascii
    $s2 = "var predecessorJKn = function(r) {" fullword ascii
    $s3 = "var sobNwG = function() {" fullword ascii
    $s4 = "    var n = String[\"fro\" + \"mC\" + \"har\" + \"Code\"];" fullword ascii
    $s5 = "        for (r = 0; r < e; r++) lookup[r] = code[r];" fullword ascii

  condition:
    uint16(0) == 0x6621 and
    all of them
}