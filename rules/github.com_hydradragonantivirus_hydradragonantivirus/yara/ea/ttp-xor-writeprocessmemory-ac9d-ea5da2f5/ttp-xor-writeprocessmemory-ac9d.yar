rule TTP_XOR_WriteProcessMemory_ac9d {
  strings:
    $key_ac9d = { fb ef [2] c9 cd [2] cf f8 [2] e1 f8 [2] de e4 }

  condition:
    any of them
}