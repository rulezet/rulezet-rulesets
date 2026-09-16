rule TTP_XOR_WriteProcessMemory_2bc8 {
  strings:
    $key_2bc8 = { 7c ba [2] 4e 98 [2] 48 ad [2] 66 ad [2] 59 b1 }

  condition:
    any of them
}