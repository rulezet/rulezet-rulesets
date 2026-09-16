rule TTP_XOR_WriteProcessMemory_2b04 {
  strings:
    $key_2b04 = { 7c 76 [2] 4e 54 [2] 48 61 [2] 66 61 [2] 59 7d }

  condition:
    any of them
}