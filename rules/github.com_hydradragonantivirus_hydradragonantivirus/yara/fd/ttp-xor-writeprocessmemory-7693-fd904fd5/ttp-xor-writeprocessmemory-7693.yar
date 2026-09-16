rule TTP_XOR_WriteProcessMemory_7693 {
  strings:
    $key_7693 = { 21 e1 [2] 13 c3 [2] 15 f6 [2] 3b f6 [2] 04 ea }

  condition:
    any of them
}