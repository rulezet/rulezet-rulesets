rule TTP_XOR_WriteProcessMemory_e818 {
  strings:
    $key_e818 = { bf 6a [2] 8d 48 [2] 8b 7d [2] a5 7d [2] 9a 61 }

  condition:
    any of them
}