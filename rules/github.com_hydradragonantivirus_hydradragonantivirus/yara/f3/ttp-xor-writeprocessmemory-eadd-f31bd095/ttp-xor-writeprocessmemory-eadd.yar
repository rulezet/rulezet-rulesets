rule TTP_XOR_WriteProcessMemory_eadd {
  strings:
    $key_eadd = { bd af [2] 8f 8d [2] 89 b8 [2] a7 b8 [2] 98 a4 }

  condition:
    any of them
}