rule TTP_XOR_WriteProcessMemory_4fbf {
  strings:
    $key_4fbf = { 18 cd [2] 2a ef [2] 2c da [2] 02 da [2] 3d c6 }

  condition:
    any of them
}