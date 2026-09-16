rule Whispergate_Stage_2 {
  meta:
    description = "Detects second stage payload from WhisperGate"
    author      = "mmuir@cadosecurity.com"
    date        = "2022-01-17"
    license     = "Apache License 2.0"
    hash        = "dcbbae5a1c61dbbbb7dcd6dc5dd1eb1169f5329958d38b58c3fd9384081c9b78"
    report      = "https://github.com/cado-security/DFIR_Resources_Whispergate"

  strings:
    $a = "m_Interceptor"
    $b = "m_b16e73e0daac4b43b6566901b5424c53"
    $c = "m_437732cee5f54d7d84add7bd3097d3ca"
    $d = "m_0db9708cf64940829f9af87edeedf60e"
    $e = "m_e143316820b14d0388a7274438ec078d"
    $f = "m_f31090c715de4b0babd31a63411046c8"
    $g = "m_611d1abc32fc4fd8a34e044f973441da"
    $h = "m_774b9210d98142ebb4413559daae5a44"

  condition:
    uint16(0) == 0x5A4D and all of them
}