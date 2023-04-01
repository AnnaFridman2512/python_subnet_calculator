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

#calc_by_hosts(26, 62)

"""Convert IP address to binary:
The IP address is split into four octets using the dot (.) as a delimiter.
For each octet, the "int" function is used to convert it into an integer.
The "bin" function is then used to convert the integer into a binary string.
The "[2:]" notation is used to remove the '0b' prefix that is added to the binary string by the "bin" function.
The "zfill" function is used to pad the binary string with zeros so that it is 8 characters long.
The resulting binary string for each octet is concatenated into a single string.
The final binary string representing the IP address is returned by the function.
"""
def mask_or_ip_to_binary(mask_or_ip): #returns a list of octets in binary
    binary_string = ''.join([bin(int(octet))[2:].zfill(8) for octet in mask_or_ip.split('.')])
    #print(binary_string)
    octets = [binary_string[i:i + 8] for i in range(0, len(binary_string), 8)]
    #print(octets)
    return octets #Example ip_binary = ['11000000', '10101000', '00000001', '00000001']  # 192.168.1.1 in binary

#mask_or_ip_to_binary("255.255.255.255")

def get_network_id(ip, subnet_mask):
    ip_octets = mask_or_ip_to_binary(ip)
    subnet_mask_octets = mask_or_ip_to_binary(subnet_mask)
    #  By performing a bitwise AND operation between the binary representation of an IP address
    #  and the binary representation of the subnet mask,
    #  we can extract the network portion of the IP address.
    # int(ip_octets[i], 2) converts the binary representation of an octet into an integer value
    # that can be used in mathematical operations. By using base 2,
    # we can convert the binary representation of an octet (e.g., '11000000') to its decimal equivalent (e.g., 192).
    network_id_octets = [str(int(ip_octets[i], 2) & int(subnet_mask_octets[i], 2)) for i in range(4)]
    # Join the octets into a dotted decimal notation
    network_id = '.'.join(network_id_octets)
    #print(network_id)
    return network_id

#get_network_id("192.168.1.10", "255.255.255.255")

def calculate_subnet_addresses_and_broadcasts(network_id, subnet_mask, num_subnets):
    # Convert the IP address and subnet mask to binary strings
    network_id_bin = ''.join([bin(int(x) + 256)[3:] for x in network_id.split('.')])
    subnet_mask_bin = ''.join([bin(int(x) + 256)[3:] for x in subnet_mask.split('.')])

    # Determine the number of bits in the subnet mask
    num_mask_bits = subnet_mask_bin.count('1')

    # Calculate the number of hosts per subnet
    num_hosts_per_subnet = 2 ** (32 - num_mask_bits) - 2

    # Calculate the block size for each subnet
    block_size = num_hosts_per_subnet // num_subnets
    if block_size <= 0 :
        print("Cannot create subnets with the given parameters, Enter how many usable subnets only")
        return
    else:
        # Calculate the new subnet mask
        new_subnet_mask_bin = '1' * num_mask_bits + '0' * (32 - num_mask_bits)
        new_subnet_mask_bin = new_subnet_mask_bin[:num_mask_bits + num_subnets.bit_length()]
        new_subnet_mask = '.'.join([str(int(new_subnet_mask_bin[i:i + 8], 2)) for i in range(0, 32, 8)])

        # Calculate the network ID, broadcast address, and usable IP address range for each subnet
        subnets = []
        for i in range(num_subnets):
            subnet_network_id_bin = network_id_bin[:num_mask_bits] + bin(
                i * block_size + int(network_id_bin[num_mask_bits:], 2))[2:].zfill(block_size.bit_length())
            subnet_network_id = '.'.join([str(int(subnet_network_id_bin[i:i + 8], 2)) for i in range(0, 32, 8)])
            subnet_broadcast_bin = subnet_network_id_bin[:num_mask_bits] + bin(
                (i + 1) * block_size + int(network_id_bin[num_mask_bits:], 2))[2:].zfill(32 - num_mask_bits)

            subnet_broadcast = '.'.join([str(int(subnet_broadcast_bin[i:i + 8], 2)) for i in range(0, 32, 8)])

            subnets.append({'subnet_network_id': subnet_network_id, 'subnet_broadcast': subnet_broadcast})
    #print(subnets)
    return subnets

#subnets = calculate_subnet_addresses_and_broadcasts('192.168.16.0', '255.255.255.0', 4)
#print(subnets)

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
                    "Type 'hosts' for calculating by hosts or type 'subnets' for calculating by number of usable subnets: ").lower()
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


            network_ID = get_network_id(ip_address, new_subnet_mask)
            subnets_and_broadcasts = calculate_subnet_addresses_and_broadcasts(network_ID, new_subnet_mask, num_of_subnets)

            if num_of_subnets and hosts_per_subnet:
                print(f'Number of subnets for {ip_address} is {num_of_subnets}')
                print(f'Number of hosts per subnet for {ip_address} is {hosts_per_subnet}')
                print(f'New subnet mask is {new_subnet_mask}')
                print(f'New CIDR is {new_CIDR}')
                print(f'Network_ID (network address) is {network_ID}')
                if len(subnets_and_broadcasts) == 1:
                    print(f'There is only one subnet, subnets IP is {list(subnets_and_broadcasts[0].items())[0][1]}, the broadcast is {list(subnets_and_broadcasts[0].items())[1][1]}')
                elif len(subnets_and_broadcasts) == 2:
                    print(f'First subnet IP is {list(subnets_and_broadcasts[0].items())[0][1]}, the broadcast is {list(subnets_and_broadcasts[0].items())[1][1]}')
                    print(f'Last subnet IP is {list(subnets_and_broadcasts[1].items())[0][1]}, the broadcast is {list(subnets_and_broadcasts[1].items())[1][1]}')
                elif len(subnets_and_broadcasts) == 3:
                    print(f'First subnet IP is {list(subnets_and_broadcasts[0].items())[0][1]}, the broadcast is {list(subnets_and_broadcasts[0].items())[1][1]}')
                    print(f'Second subnet IP is {list(subnets_and_broadcasts[1].items())[0][1]}, the broadcast is {list(subnets_and_broadcasts[1].items())[1][1]}')
                    print(f'Last subnet IP is {list(subnets_and_broadcasts[-1].items())[0][1]}, the broadcast is {list(subnets_and_broadcasts[-1].items())[1][1]}')
                else:
                    print(f'First subnet IP is {list(subnets_and_broadcasts[0].items())[0][1]}, the broadcast is {list(subnets_and_broadcasts[0].items())[1][1]}')
                    print(f'Second subnet IP is {list(subnets_and_broadcasts[1].items())[0][1]}, the broadcast is {list(subnets_and_broadcasts[1].items())[1][1]}')
                    print(f'One before Last subnet IP is {list(subnets_and_broadcasts[-2].items())[0][1]}, the broadcast is {list(subnets_and_broadcasts[-2].items())[1][1]}')
                    print(f'Last subnet IP is {list(subnets_and_broadcasts[-1].items())[0][1]}, the broadcast is {list(subnets_and_broadcasts[-1].items())[1][1]}')

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

