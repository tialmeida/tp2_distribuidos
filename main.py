import pyshark
import matplotlib.pyplot as plt
import socket

FILE_PATH = "./raw/Cap2.pcapng"


def layers_to_layers_name_list(layers):
    layers_name_list = []

    for layer in layers:
        layers_name_list.append(layer.layer_name)

    return layers_name_list


def add_or_plus_layer(layer):
    if layer != 'eth':
        add_or_plus(layer, protocols)


def add_or_plus(item, dictionary):
    if dictionary.get(item) is not None:
        dictionary[item] += 1
    else:
        dictionary[item] = 1


def add_or_plus_using_key_and_value(key, value, dictionary):
    if dictionary.get(key) is not None:
        dictionary[key] += value
    else:
        dictionary[key] = value


def average(numbers):
    length = len(numbers)
    summation = 0

    for number in numbers:
        summation += number

    return summation / length


def dictionary_to_list(keys, dictionary):
    values = []

    for key in keys:
        values.append(dictionary[key])

    return values


def get_five_biggers(dictionary):
    list_items = list(dictionary.items())

    for item in list_items:
        if item[0] == socket.gethostbyname(socket.gethostname()):
            list_items.remove(item)

    list_items.sort(key=get_second, reverse=True)
    return list_items[0:5]


def get_second(element):
    return element[1]


def list_pair_to_two_lists(list_pair):
    list_1 = []
    list_2 = []

    for item in list_pair:
        item_1, item_2 = item
        list_1.append(item_1)
        list_2.append(item_2)

    return list_1, list_2


capture = pyshark.FileCapture(FILE_PATH)
protocols = {}
sources = {}
destinations = {}
lengths = {}

for packet in capture:
    layers_names = layers_to_layers_name_list(packet.layers)

    for layer_name in layers_names:
        add_or_plus_layer(layer_name.lower())

    if 'ip' in layers_names:
        add_or_plus(packet.ip.src, sources)
        add_or_plus(packet.ip.dst, destinations)
        add_or_plus_using_key_and_value(packet.ip.src, int(packet.length), lengths)


protocols_name = protocols.keys()
protocols_value = dictionary_to_list(protocols_name, protocols)
plt.title("Quantidade por protocolos")
plt.xlabel('Protocolos')
plt.ylabel('Quantidade')
plt.plot(protocols_name, protocols_value, 'k--')
plt.plot(protocols_name, protocols_value, 'go')
plt.show()

five_biggers_sources = get_five_biggers(sources)
names_sources, values_sources = list_pair_to_two_lists(five_biggers_sources)
plt.title("Top 5 sources")
plt.xlabel('Sources')
plt.ylabel('Quantidade')
plt.bar(names_sources, values_sources)
plt.show()

five_biggers_destinations = get_five_biggers(destinations)
names_destinations, values_destinations = list_pair_to_two_lists(five_biggers_destinations)
plt.title("Top 5 destinations")
plt.xlabel('Destinations')
plt.ylabel('Quantidade')
plt.bar(names_destinations, values_destinations)
plt.show()

five_biggers_lengths = get_five_biggers(lengths)
names_sources_lengths, values_sources_lengths = list_pair_to_two_lists(five_biggers_lengths)
lengths_average = average(values_sources_lengths)
plt.title("Top 5 packet sizes")
plt.xlabel('Sources')
plt.ylabel('Sum packet sizes')
plt.bar(names_sources_lengths, values_sources_lengths)
plt.axhline(y=lengths_average, color='green', linestyle='--', linewidth=2, label='Average')
plt.show()
