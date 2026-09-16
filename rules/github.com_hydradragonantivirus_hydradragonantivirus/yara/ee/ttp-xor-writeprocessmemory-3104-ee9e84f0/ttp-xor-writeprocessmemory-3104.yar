rule TTP_XOR_WriteProcessMemory_3104 {
  strings:
    $key_3104 = { 66 76 [2] 54 54 [2] 52 61 [2] 7c 61 [2] 43 7d }

  condition:
    any of them
}