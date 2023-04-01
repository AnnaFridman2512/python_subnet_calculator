import math
import re


def check_ip(ip_str):  # Will return True or False  (verify – hint: regex)
    return bool(
        re.match(r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$', ip_str))


# check_ip("192.168.0.1")

def calc_network_class(ip_str):
    ip_list = ip_str.split('.')
    first_octate = int(ip_list[0])
    if first_octate <= 126:
        network_class = "A"
    elif first_octate <= 191:
        network_class = "B"
    elif first_octate <= 223:
        network_class = "C"
    else:
        print("Not valid IP address")
    # print(network_class)
    return network_class


# calc_network_class("224.0.0.1")
def calc_CIDR(ip_str):  # Calculates the CIDR by class table and return the CIDR
    network_class = calc_network_class(ip_str)
    if network_class == "A":
        calculated_CIDR = 8
    elif network_class == "B":
        calculated_CIDR = 16
    elif network_class == "C":
        calculated_CIDR = 24
    else:
        print("IP is not valid")
    return calculated_CIDR


# calc_CIDR("192.168.0.1")



def check_CIDR_match_network(user_CIDR, ip_address):  # Cheks if CIDR valid for given IP address
    user_CIDR = int(user_CIDR)
    if not 1 <= user_CIDR <= 32:
        print("Enter only numbers between 1 and 32")
    else:
        network_class = calc_network_class(ip_address)

        # If the network is class A CIDR should be from /8 to /1
        if user_CIDR <= 8 and network_class == "A":
            # print("True")
            return True

        # If the network is class B CIDR should be from /16 to /9
        elif 9 <= user_CIDR <= 16 and network_class == "B":
            # print("True")
            return True
        # If the network is class C CIDR should be from /31 to /17
        elif 17 <= user_CIDR <= 31 and network_class == "C":
            # print("True")
            return True
        else:
            # print("False")
            return False


# check_CIDR_match_network(16, "192.168.0.1")


def calc_by_subnets(cidr, num_of_subnets):
    # Calculate the number of bits needed for the subnets
    # bit_length() is a method in Python that returns the number of bits required to represent an integer in binary
    num_bits = num_of_subnets.bit_length() - 1
    new_CIDR = cidr + num_bits
    # 0xffffffff is a 32-bit integer with all bits set to 1. This is a binary number that represents the largest possible IP address (255.255.255.255) in binary format.
    # (0xffffffff << (32 - new_CIDR)) shifts the 1s in 0xffffffff to the left by (32 - new_CIDR) bits, effectively setting the first (32 - new_CIDR) bits of the 32-bit integer to 1, and the remaining bits to 0. This gives us the subnet mask in binary format.
    subnet_mask = '.'.join([str((0xffffffff << (32 - new_CIDR) >> i) & 0xff) for i in [24, 16, 8, 0]])
    hosts_per_subnet = 2 ** (32 - new_CIDR) - 2
    #print(f'new CIDR {new_CIDR}')
    #print(f'new subnet mask {subnet_mask}')
    #print(f'Number of hosts per subnet {hosts_per_subnet}')
    return new_CIDR, subnet_mask, hosts_per_subnet

#calc_by_subnets(24, 4)

def calc_by_hosts(cidr, num_of_hosts):
    # Calculate the number of bits needed for the hosts
    # bit_length() is a method in Python that returns the number of bits required to represent an integer in binary
    num_bits = (num_of_hosts + 2).bit_length() - 1 # adding 2 to account for the network and broadcast addresses
    new_CIDR = cidr + num_bits
    # 0xffffffff is a 32-bit integer with all bits set to 1. This is a binary number that represents the largest possible IP address (255.255.255.255) in binary format.
    # (0xffffffff << (32 - new_CIDR)) shifts the 1s in 0xffffffff to the left by (32 - new_CIDR) bits,
    # effectively setting the first (32 - new_CIDR) bits of the 32-bit integer to 1, and the remaining bits to 0.
    # This gives us the subnet mask in binary format.
    new_subnet_mask = '.'.join([str((0xffffffff << (32 - new_CIDR) >> i) & 0xff) for i in [24, 16, 8, 0]])
    num_subnets = 2 ** (32 - new_CIDR)
    #print(f'new CIDR {new_CIDR}')
    #print(f'new subnet mask {subnet_mask}')
    #print(f'Number of subnets {num_subnets}')
    return new_CIDR, new_subnet_mask, num_subnets

#calc_by_hosts(24, 62)

"""Convert IP address to binary:
The IP address is split into four octets using the dot (.) as a delimiter.
For each octet, the "int" function is used to convert it into an integer.
The "bin" function is then used to convert the integer into a binary string.
The "[2:]" notation is used to remove the '0b' prefix that is added to the binary string by the "bin" function.
The "zfill" function is used to pad the binary string with zeros so that it is 8 characters long.
The resulting binary string for each octet is concatenated into a single string.
The final binary string representing the IP address is returned by the function.
"""
def ip_to_binary(ip):
    binary_IP = ''.join([bin(int(octet))[2:].zfill(8) for octet in ip.split('.')])
    #print(binary_IP)
    return binary_IP

#ip_to_binary("192.168.0.1")

def sub_calc():
    ip_address = input("Please enter an IP address: ")
    if ip_address:
        if check_ip(ip_address):
            while True:
                user_CIDR = input("Enter CIDR: ")
                if not user_CIDR:
                    # calculate the CIDR by IP class
                    cidr = calc_CIDR(ip_address)
                    print("Given IP Cidr " + str(cidr))
                    break
                else:
                    user_CIDR = int(user_CIDR)
                    # check if CIDR is right for the IP
                    if check_CIDR_match_network(user_CIDR, ip_address):
                        cidr = user_CIDR
                        print("Given Cidr " + str(cidr))
                        break
                    else:
                        print("CIDR you entered is not valid for the IP you entered")


            while True:
                num_of_hosts_or_subnets = input(
                    "Type 'hosts' for calculating by hosts or type 'subnets' for calculating by number of subnets: ").lower()
                if num_of_hosts_or_subnets == "hosts":
                    hosts_per_subnet = int(input("Enter number of hosts: "))
                    new_CIDR, new_subnet_mask, num_of_subnets = calc_by_hosts(cidr, hosts_per_subnet)
                    break
                elif num_of_hosts_or_subnets == "subnets":
                    num_of_subnets = int(input("Enter number of subnets: "))
                    new_CIDR, new_subnet_mask, hosts_per_subnet = calc_by_subnets(cidr, num_of_subnets)
                    break
                else:
                    print("Type only 'subnets' or 'hosts' ")

            if num_of_subnets and hosts_per_subnet:
                print(f'Number of subnets for {ip_address} is {num_of_subnets}')
                print(f'Number of hosts per subnet for {ip_address} is {hosts_per_subnet}')
                print(f'new subnet mask is {new_subnet_mask}')
                print(f'New CIDR is {new_CIDR}')

                # first subnet network address and its Broadcast
                # second subnet network address and its Broadcast
                # one before last subnet network address and its Broadcast
                # last subnet network address and its Broadcast
        else:
            print("IP not valid")
            sub_calc()
    else:
        print("Cant proceed without address")
        sub_calc()


if __name__ == '__main__':
    sub_calc()

