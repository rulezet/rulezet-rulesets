rule TTP_XOR_WriteProcessMemory_0aa8 {
  strings:
    $key_0aa8 = { 5d da [2] 6f f8 [2] 69 cd [2] 47 cd [2] 78 d1 }

  condition:
    any of them
}