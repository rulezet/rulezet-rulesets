rule TTP_XOR_WriteProcessMemory_2812 {
  strings:
    $key_2812 = { 7f 60 [2] 4d 42 [2] 4b 77 [2] 65 77 [2] 5a 6b }

  condition:
    any of them
}