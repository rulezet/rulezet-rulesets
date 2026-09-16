rule TTP_XOR_WriteProcessMemory_eecc {
  strings:
    $key_eecc = { b9 be [2] 8b 9c [2] 8d a9 [2] a3 a9 [2] 9c b5 }

  condition:
    any of them
}