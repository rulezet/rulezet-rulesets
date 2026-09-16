rule md5_c647e85ad77fd9971ba709a08566935d {
    strings: $ = "fopen(\"cache.php\", \"w+\")"
    condition: any of them
}