import truecase
import contractions
import nltk
import re
nltk.download('maxent_ne_chunker')
nltk.download('words')
nltk.download('punkt')
nltk.download('averaged_perceptron_tagger')


# make upper and lower case correctly for contractions
# Inputs like "I don't think" should become "I do not think"
# change everything back to lower case to work better with words
def normalize_input(sentence):
    sentence = truecase.get_true_case(sentence)
    sentence = contractions.fix(sentence)
    sentence = sentence.lower()

    return sentence


def entities(sentence):
    # I could have simply checked if there is a name in the string of the action request that is in the phonebook -
    # named entity recognition is something important for a chatbot, so I wanted to try if I can get it implemented here

    # it is actually supposed to check for the label 'PERSON' -- the nltk library didn't recognize german names as a person, though
    # and the spacy library did not work either, which is why I stayed with 'label' as chunk attribute --> this worked
    # I didn't want to just use regex to search for the names in the text, since we probably won't know them in the later application area
    # Therefore it is better to simply recognize names
    # With more time, we should fine-tune a pos-tag model on our data(german names) as well in order for this to work

    sentence = truecase.get_true_case(sentence)  # we need the correct upper and lower case so that the tagger recognizes the correct pos tags
    sentence = re.sub("[^-9A-Za-z ]", "", sentence)
    for sent in nltk.sent_tokenize(sentence):
        for chunk in nltk.ne_chunk(nltk.pos_tag(nltk.word_tokenize(sent))):
            for w in chunk:
                if w == 'Hans':
                    name = w
                break
            if hasattr(chunk, 'label'):
                name = ' '.join(c[0] for c in chunk)

    return name