rule TTP_XOR_QUAD_CurrentVersionRun_adaf {
  strings:
    $key_adaf = { fe c0 [2] da ce [2] f1 e2 [2] df c0 [2] cb db [2] c4 c1 [2] da dc [2] d8 dd [2] c3 db [2] df dc [2] c3 f3 }

  condition:
    any of them
}