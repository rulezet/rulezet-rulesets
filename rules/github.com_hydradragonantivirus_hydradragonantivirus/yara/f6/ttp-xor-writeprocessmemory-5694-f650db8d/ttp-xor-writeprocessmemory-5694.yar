rule TTP_XOR_WriteProcessMemory_5694 {
  strings:
    $key_5694 = { 01 e6 [2] 33 c4 [2] 35 f1 [2] 1b f1 [2] 24 ed }

  condition:
    any of them
}