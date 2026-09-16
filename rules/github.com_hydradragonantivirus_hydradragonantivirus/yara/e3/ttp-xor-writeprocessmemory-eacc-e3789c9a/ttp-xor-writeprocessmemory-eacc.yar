rule TTP_XOR_WriteProcessMemory_eacc {
  strings:
    $key_eacc = { bd be [2] 8f 9c [2] 89 a9 [2] a7 a9 [2] 98 b5 }

  condition:
    any of them
}