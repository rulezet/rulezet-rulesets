rule TTP_XOR_WriteProcessMemory_1e18 {
  strings:
    $key_1e18 = { 49 6a [2] 7b 48 [2] 7d 7d [2] 53 7d [2] 6c 61 }

  condition:
    any of them
}