rule TTP_XOR_WriteProcessMemory_6aa8 {
  strings:
    $key_6aa8 = { 3d da [2] 0f f8 [2] 09 cd [2] 27 cd [2] 18 d1 }

  condition:
    any of them
}