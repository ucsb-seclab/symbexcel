import networkx as nx


def generate_graph(simgr, formula=False):
    G = nx.DiGraph()
    for state in simgr.states:
        if formula:
            history = ['ENTRY_POINT'] + state.formula_log
        else:
            history = ['ENTRY_POINT'] + state.handlers_log
            # history = []
            #
            # for i,h in enumerate(_history):
            #     tokens = h.split('_')
            #     history += [str(i)+'_'.join(sorted(set(tokens), key=tokens.index))]

        # Filter empty values
        history = [h for h in history if h]
        edges = zip(history, history[1:])
        for a, b in edges:
            G.add_edge(nx.readwrite.gml.escape(a), nx.readwrite.gml.escape(b))
            G.nodes[nx.readwrite.gml.escape(a)]['label'] = nx.readwrite.gml.escape(a[:50])
            G.nodes[nx.readwrite.gml.escape(b)]['label'] = nx.readwrite.gml.escape(b[:50])

    for n in G.nodes:
        G.nodes[n]['shape'] = 'box'
        G.nodes[n]['style'] = 'rounded'
        G.nodes[n]['colorscheme'] = 'spectral6'

    # mark symbolic nodes
    for n in G.nodes:
        if n.startswith('*'):
            G.nodes[n]['style'] = 'rounded,filled'
            G.nodes[n]['color'] = '5'

    # mark last node if timed out
    for state in simgr.states:
        if state.error:
            node = nx.readwrite.gml.escape(history[-1])

            G.nodes[node]['style'] = 'rounded,filled'
            if state.error == 'TimeoutError':
                G.nodes[node]['color'] = '2'
            else:
                G.nodes[node]['color'] = '1'

    # remove * and leading underscore
    for n in G.nodes:
        G.nodes[n]['label'] = n
        if G.nodes[n]['label'].startswith('*'):
            G.nodes[n]['label'] = G.nodes[n]['label'][1:]
        if G.nodes[n]['label'].startswith('_'):
            G.nodes[n]['label'] = G.nodes[n]['label'][1:]

    return G
