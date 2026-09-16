rule TTP_XOR_WriteProcessMemory_f854 {
  strings:
    $key_f854 = { af 26 [2] 9d 04 [2] 9b 31 [2] b5 31 [2] 8a 2d }

  condition:
    any of them
}