rule TTP_XOR_WriteProcessMemory_7634 {
  strings:
    $key_7634 = { 21 46 [2] 13 64 [2] 15 51 [2] 3b 51 [2] 04 4d }

  condition:
    any of them
}