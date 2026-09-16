rule TTP_XOR_WriteProcessMemory_5aa8 {
  strings:
    $key_5aa8 = { 0d da [2] 3f f8 [2] 39 cd [2] 17 cd [2] 28 d1 }

  condition:
    any of them
}