rule TTP_XOR_WriteProcessMemory_1fd0 {
  strings:
    $key_1fd0 = { 48 a2 [2] 7a 80 [2] 7c b5 [2] 52 b5 [2] 6d a9 }

  condition:
    any of them
}