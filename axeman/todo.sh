cat foo2 | grep -v '(J)' | grep -P '^[^0]\d{1,5}\t' | awk '{print $4}'  | xargs -L 1 ./simple.py -c 2>&1 | grep 'To continue' > todo.txt
sed -i 's/-u/-x -n -u/' todo.txt
sed -i 's/^.*: //' todo.txt
bash todo.txt
