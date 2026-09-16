rule TTP_XOR_WriteProcessMemory_c632 {
  strings:
    $key_c632 = { 91 40 [2] a3 62 [2] a5 57 [2] 8b 57 [2] b4 4b }

  condition:
    any of them
}