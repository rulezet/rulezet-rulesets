rule fastcash_aix_pvpa {
  meta:
    author = "Paul Melson @pmelson"
    description = "HIDDEN COBRA AIX FastCash pvpa binary (may not be malicious, low attribution confidence)"
    reference = "https://www.us-cert.gov/ncas/alerts/TA18-275A"
    reference = "https://github.com/fboldewin/FastCashMalwareDissected/"
    sample_sha256 = "f3e521996c85c0cdb2bfb3a0fd91eb03e25ba6feef2ba3a1da844f1b17278dd2"
  strings:
    $symbol_static = { 00 5f 24 53 54 41 54 49 43 00 }
    $symbol_pvpa = { 00 00 00 00 70 76 70 61 00 00 00 00 }
    $symbol_get_pvpa = { 00 2e 67 65 74 5f 70 76 70 61 00 }
    $symbol_get_posn = { 00 2e 73 65 74 5f 70 6f 73 6e 00 }
    $symbol_init_pvpa = { 00 2e 69 6e 69 74 5f 70 76 70 61 00 }
    $string0 = "/dev/mem"
    $string1 = "set_posn"
    $string2 = "get_pvpa"
    $string3 = "init_pvpa"
    $string4 = "high_cpuid=%d"
    $string5 = "open kernel mem"
    $string6 = "cpu %d, old value = 0x%02x"
    $string7 = "Usage: pvpa [<new_value> <old_value>]"
    $string8 = "Invalid PVPA read, magic = 0x%08x, len = %d, cpu = %d"
  condition:
    uint16(0) == 0xf701 and (all of ($symbol*) or all of ($string*))
}