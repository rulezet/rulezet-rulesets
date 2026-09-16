rule TTP_XOR_WriteProcessMemory_8dbf {
  strings:
    $key_8dbf = { da cd [2] e8 ef [2] ee da [2] c0 da [2] ff c6 }

  condition:
    any of them
}