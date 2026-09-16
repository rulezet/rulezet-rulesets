rule TTP_XOR_WriteProcessMemory_2694 {
  strings:
    $key_2694 = { 71 e6 [2] 43 c4 [2] 45 f1 [2] 6b f1 [2] 54 ed }

  condition:
    any of them
}