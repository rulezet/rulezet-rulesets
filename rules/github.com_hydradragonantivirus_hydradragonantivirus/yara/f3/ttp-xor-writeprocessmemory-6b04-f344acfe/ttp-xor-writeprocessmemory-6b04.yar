rule TTP_XOR_WriteProcessMemory_6b04 {
  strings:
    $key_6b04 = { 3c 76 [2] 0e 54 [2] 08 61 [2] 26 61 [2] 19 7d }

  condition:
    any of them
}