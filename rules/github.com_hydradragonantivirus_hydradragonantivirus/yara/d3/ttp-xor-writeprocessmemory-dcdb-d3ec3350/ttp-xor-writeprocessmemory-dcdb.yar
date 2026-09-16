rule TTP_XOR_WriteProcessMemory_dcdb {
  strings:
    $key_dcdb = { 8b a9 [2] b9 8b [2] bf be [2] 91 be [2] ae a2 }

  condition:
    any of them
}