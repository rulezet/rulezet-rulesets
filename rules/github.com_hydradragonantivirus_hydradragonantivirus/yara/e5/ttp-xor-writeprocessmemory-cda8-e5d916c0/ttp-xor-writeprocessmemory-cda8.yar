rule TTP_XOR_WriteProcessMemory_cda8 {
  strings:
    $key_cda8 = { 9a da [2] a8 f8 [2] ae cd [2] 80 cd [2] bf d1 }

  condition:
    any of them
}