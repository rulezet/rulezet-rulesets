rule TTP_XOR_WriteProcessMemory_4c18 {
  strings:
    $key_4c18 = { 1b 6a [2] 29 48 [2] 2f 7d [2] 01 7d [2] 3e 61 }

  condition:
    any of them
}