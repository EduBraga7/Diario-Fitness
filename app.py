# --- Bibliotecas ---
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, abort
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from sqlalchemy.orm import joinedload
from datetime import datetime, timedelta
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user

# --- Instancia da aplicação Flask---
app = Flask(__name__)
app.secret_key = 'SEGREDO'
bcrypt = Bcrypt(app)

# --- Configuração do LoginManager ---
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'
login_manager.login_message = 'Por favor, faça o login para acessar esta página.'

# --- BANCO DE DADOS ---
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# --- Instancia do banco de dados ---
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# --- Carregador de Usuário (User Loader) ---
@login_manager.user_loader
def load_user(user_id):
    return Usuario.query.get(int(user_id))

# --- Filtro Jinja Personalizado para Horário Local ---
@app.template_filter('local_time')
def format_datetime_local(dt, fmt='%H:%M'):
    if dt is None: return ''
    dt_local = dt - timedelta(hours=3) # Ajuste se necessário
    return dt_local.strftime(fmt)

@app.context_processor
def inject_now():
    return {'now': datetime.utcnow}

# --- Models ---
class Usuario(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), unique=True, nullable=False)
    senha = db.Column(db.String(100), nullable=False)
    treinos = db.relationship("Treino", backref="usuario", lazy=True, cascade="all, delete-orphan")
    medicoes = db.relationship("Medicao", backref="usuario", lazy=True, cascade="all, delete-orphan")
    templates = db.relationship("TreinoTemplate", backref="usuario", lazy=True, cascade="all, delete-orphan")

class Medicao(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    data_medicao = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    peso_kg = db.Column(db.Float, nullable=False)
    circunferencia_braco_cm = db.Column(db.Float)
    circunferencia_cintura_cm = db.Column(db.Float)
    id_usuario = db.Column(db.Integer, db.ForeignKey("usuario.id"), nullable=False)

class Exercicio(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), unique=True, nullable=False)
    grupo_muscular = db.Column(db.String(50), nullable=False)
    id_usuario = db.Column(db.Integer, db.ForeignKey('usuario.id'), nullable=False)
    dono = db.relationship('Usuario', backref=db.backref('exercicios', lazy=True))
    registros = db.relationship("ExercicioRegistrado", lazy=True)
    db.UniqueConstraint('nome', 'id_usuario', name='uq_nome_usuario_exercicio')


class Treino(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    data_treino = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    hora_inicio = db.Column(db.DateTime)
    hora_fim = db.Column(db.DateTime)
    id_usuario = db.Column(db.Integer, db.ForeignKey("usuario.id"), nullable=False)
    exercicios_registrados = db.relationship("ExercicioRegistrado", backref="treino", lazy=True, cascade="all, delete-orphan")

class ExercicioRegistrado(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    id_treino = db.Column(db.Integer, db.ForeignKey("treino.id"), nullable=False)
    id_exercicio = db.Column(db.Integer, db.ForeignKey("exercicio.id"), nullable=False)
    observacoes = db.Column(db.Text, nullable=True)
    series = db.relationship("Serie", backref="exercicio_registrado", lazy=True, cascade="all, delete-orphan")
    exercicio = db.relationship("Exercicio", lazy=True)

class Serie(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    numero_serie = db.Column(db.Integer, nullable=False)
    repeticoes = db.Column(db.Integer, nullable=False)
    peso_kg = db.Column(db.Float, nullable=False)
    id_exercicio_registrado = db.Column(db.Integer, db.ForeignKey("exercicio_registrado.id"), nullable=False)

class TreinoTemplate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(150), nullable=False)
    id_usuario = db.Column(db.Integer, db.ForeignKey('usuario.id'), nullable=False)
    exercicios_template = db.relationship('TemplateExercicio', backref='template', lazy=True, cascade="all, delete-orphan")
    db.UniqueConstraint('nome', 'id_usuario', name='uq_nome_usuario_template')

class TemplateExercicio(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ordem = db.Column(db.Integer)
    id_template = db.Column(db.Integer, db.ForeignKey('treino_template.id'), nullable=False)
    id_exercicio = db.Column(db.Integer, db.ForeignKey('exercicio.id'), nullable=False)
    exercicio = db.relationship('Exercicio', lazy=True)

# --- Rotas de Autenticação ---
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated: return redirect(url_for('index'))
    if request.method == 'POST':
        nome_usuario = request.form.get('nome'); senha_plana = request.form.get('senha')
        if not nome_usuario or not senha_plana: flash('Nome e senha são obrigatórios.', 'error'); return redirect(url_for('register'))
        usuario_existente = Usuario.query.filter_by(nome=nome_usuario).first()
        if usuario_existente: flash('Nome de usuário já em uso.', 'error'); return redirect(url_for('register'))
        senha_hash = bcrypt.generate_password_hash(senha_plana).decode('utf-8')
        novo_usuario = Usuario(nome=nome_usuario, senha=senha_hash)
        db.session.add(novo_usuario); db.session.commit()
        flash('Conta criada! Por favor, faça o login.', 'success'); return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated: return redirect(url_for('index'))
    if request.method == 'POST':
        nome_usuario = request.form.get('nome'); senha_plana = request.form.get('senha')
        usuario = Usuario.query.filter_by(nome=nome_usuario).first()
        if usuario and bcrypt.check_password_hash(usuario.senha, senha_plana):
            login_user(usuario, remember=True); flash('Login realizado com sucesso!', 'success')
            next_page = request.args.get('next'); return redirect(next_page) if next_page else redirect(url_for('index'))
        else: flash('Login falhou. Verifique usuário e senha.', 'error')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user(); flash('Você saiu da sua conta.', 'info'); return redirect(url_for('login'))

# --- Rotas Principais da Aplicação ---
@app.route("/")
@login_required
def index():
    lista_de_exercicios = Exercicio.query.filter_by(id_usuario=current_user.id).all()
    lista_de_treinos = Treino.query.filter_by(id_usuario=current_user.id).order_by(Treino.data_treino.desc()).all()
    lista_de_templates = TreinoTemplate.query.filter_by(id_usuario=current_user.id).order_by(TreinoTemplate.nome).all()
    treino_ativo = Treino.query.filter_by(id_usuario=current_user.id, hora_fim=None).order_by(Treino.id.desc()).first()
    return render_template("index.html", exercicios=lista_de_exercicios, treinos=lista_de_treinos, templates=lista_de_templates, treino_ativo=treino_ativo)

# --- Rotas de Exercício (Biblioteca - Global) ---
@app.route("/add_exercicio", methods=["GET", "POST"])
@login_required
def add_exercicio():
    if request.method == "POST":
        nome = request.form.get("nome_exercicio")
        grupo = request.form.get("grupo_muscular")
        exercicio_existente = Exercicio.query.filter_by(nome=nome, id_usuario=current_user.id).first()

        if exercicio_existente:
            flash(f'Erro: Você já cadastrou o exercício "{nome}".', 'error')
        elif not nome or not grupo:
            flash(f'Erro: Campos obrigatórios.', 'error')
        else:
            novo_exercicio = Exercicio(nome=nome, 
                                     grupo_muscular=grupo, 
                                     id_usuario=current_user.id)
            db.session.add(novo_exercicio)
            db.session.commit()
            flash(f'Exercício "{nome}" cadastrado!', 'success')
        return redirect(url_for("add_exercicio"))
    return render_template("add_exercicio.html")

@app.route('/exercicio/<int:exercicio_id>/delete', methods=['POST'])
@login_required
def delete_exercicio_biblioteca(exercicio_id):
    exercicio_para_excluir = Exercicio.query.get_or_404(exercicio_id)
    if exercicio_para_excluir.id_usuario != current_user.id:
        abort(403)
    registros_associados = ExercicioRegistrado.query.filter_by(id_exercicio=exercicio_id).count()

    if registros_associados > 0:
        flash(f'Erro: Exercício "{exercicio_para_excluir.nome}" está usado em treinos e não pode ser excluído.', 'error')
    else:
        db.session.delete(exercicio_para_excluir)
        db.session.commit()
        flash(f'Exercício "{exercicio_para_excluir.nome}" excluído.', 'success')
    return redirect(url_for('index'))

@app.route('/exercicio/<int:exercicio_id>/detalhes')
@login_required
def ver_exercicio_detalhes(exercicio_id):
    exercicio = Exercicio.query.get_or_404(exercicio_id)
    if exercicio.id_usuario != current_user.id:
        abort(403)
    registros_do_exercicio = ExercicioRegistrado.query.join(Treino).filter(
        ExercicioRegistrado.id_exercicio == exercicio_id, 
        Treino.id_usuario == current_user.id
    ).order_by(Treino.data_treino.desc()).options(
        joinedload(ExercicioRegistrado.series), 
        joinedload(ExercicioRegistrado.treino)
    ).all()
    serie_recorde = None
    max_peso_encontrado = 0 
    if registros_do_exercicio: 
        for registro in registros_do_exercicio:
            for serie in registro.series:
                if serie.peso_kg is not None and serie.peso_kg > max_peso_encontrado: 
                    max_peso_encontrado = serie.peso_kg
                    serie_recorde = serie
    return render_template(
        'exercicio_detalhes.html', 
        exercicio=exercicio, 
        registros=registros_do_exercicio, 
        recorde=serie_recorde
    )

@app.route('/api/exercicio/<int:exercicio_id>/progressao')
@login_required
def api_exercicio_progressao(exercicio_id):
    registros = ExercicioRegistrado.query.join(Treino).filter(ExercicioRegistrado.id_exercicio == exercicio_id, Treino.id_usuario == current_user.id).order_by(Treino.data_treino.asc()).options(joinedload(ExercicioRegistrado.series), joinedload(ExercicioRegistrado.treino)).all()
    max_peso_por_data = {}
    for registro in registros:
        data_str = registro.treino.data_treino.strftime('%d/%m/%Y'); max_peso_neste_dia = 0
        pesos_validos = [s.peso_kg for s in registro.series if s.peso_kg is not None] 
        if pesos_validos: max_peso_neste_dia = max(pesos_validos) 
        if max_peso_neste_dia > 0:
            if data_str not in max_peso_por_data or max_peso_neste_dia > max_peso_por_data[data_str]:
                max_peso_por_data[data_str] = max_peso_neste_dia
    datas = list(max_peso_por_data.keys()); pesos_maximos = list(max_peso_por_data.values())
    return jsonify(labels=datas, data=pesos_maximos)

# --- Rotas de Medição (User-Specific) ---
@app.route('/add_medicao', methods=['GET', 'POST'])
@login_required
def add_medicao():
    if request.method == 'POST':
        peso = request.form.get('peso_kg'); braco = request.form.get('circunferencia_braco_cm'); cintura = request.form.get('circunferencia_cintura_cm')
        if not peso: flash('Erro: Peso obrigatório.', 'error'); return redirect(url_for('add_medicao'))
        try: peso_float = float(peso); braco_float = float(braco) if braco else None; cintura_float = float(cintura) if cintura else None
        except ValueError: flash('Erro: Valores numéricos inválidos.', 'error'); return redirect(url_for('add_medicao'))
        nova_medicao = Medicao(id_usuario=current_user.id, peso_kg=peso_float, circunferencia_braco_cm=braco_float, circunferencia_cintura_cm=cintura_float)
        db.session.add(nova_medicao); db.session.commit(); flash('Medição registrada!', 'success')
        return redirect(url_for('add_medicao'))
    return render_template('add_medicao.html')

@app.route('/historico_medicoes')
@login_required
def historico_medicoes():
    medicoes_passadas = Medicao.query.filter_by(id_usuario=current_user.id).order_by(Medicao.data_medicao.desc()).all()
    return render_template('historico_medicoes.html', medicoes=medicoes_passadas)

@app.route('/api/peso_historico')
@login_required
def api_peso_historico():
    medicoes = Medicao.query.filter_by(id_usuario=current_user.id).order_by(Medicao.data_medicao.asc()).all()
    datas = [m.data_medicao.strftime('%d/%m/%Y') for m in medicoes]; pesos = [m.peso_kg for m in medicoes]
    return jsonify(labels=datas, data=pesos)

@app.route('/medicao/<int:medicao_id>/edit', methods=['GET'])
@login_required
def edit_medicao_page(medicao_id):
    medicao_para_editar = Medicao.query.get_or_404(medicao_id)
    if medicao_para_editar.id_usuario != current_user.id: abort(403)
    return render_template('edit_medicao.html', medicao=medicao_para_editar)

@app.route('/medicao/<int:medicao_id>/update', methods=['POST'])
@login_required
def update_medicao(medicao_id):
    medicao_para_atualizar = Medicao.query.get_or_404(medicao_id)
    if medicao_para_atualizar.id_usuario != current_user.id: abort(403)
    novo_peso = request.form.get('peso_kg'); novo_braco = request.form.get('circunferencia_braco_cm'); novo_cintura = request.form.get('circunferencia_cintura_cm')
    if not novo_peso: flash('Erro: Peso obrigatório.', 'error'); return redirect(url_for('edit_medicao_page', medicao_id=medicao_id))
    try: peso_float = float(novo_peso); braco_float = float(novo_braco) if novo_braco else None; cintura_float = float(novo_cintura) if novo_cintura else None
    except ValueError: flash('Erro: Valores numéricos inválidos.', 'error'); return redirect(url_for('edit_medicao_page', medicao_id=medicao_id))
    medicao_para_atualizar.peso_kg = peso_float; medicao_para_atualizar.circunferencia_braco_cm = braco_float; medicao_para_atualizar.circunferencia_cintura_cm = cintura_float
    db.session.commit(); flash('Medição atualizada!', 'success'); return redirect(url_for('historico_medicoes'))

@app.route('/medicao/<int:medicao_id>/delete', methods=['POST'])
@login_required
def delete_medicao(medicao_id):
    medicao_para_excluir = Medicao.query.get_or_404(medicao_id)
    if medicao_para_excluir.id_usuario != current_user.id: abort(403)
    try: db.session.delete(medicao_para_excluir); db.session.commit(); flash('Medição excluída.', 'success')
    except Exception as e: db.session.rollback(); flash(f'Erro: {e}', 'error')
    return redirect(url_for('historico_medicoes'))

# --- Rotas de Treino (User-Specific) ---
@app.route("/novo_treino", methods=['GET', 'POST'])
@login_required
def novo_treino():
    template_id = None
    if request.method == 'POST':
        template_id_str = request.form.get('template_id')
        if template_id_str:
            try: template_id = int(template_id_str)
            except ValueError: flash('ID de modelo inválido.', 'error'); return redirect(url_for('index'))
    novo_treino_obj = Treino(id_usuario=current_user.id, hora_inicio=datetime.utcnow()); db.session.add(novo_treino_obj); db.session.flush()
    if template_id:
        template_selecionado = TreinoTemplate.query.get(template_id)
        if template_selecionado and template_selecionado.id_usuario == current_user.id:
            for template_ex in template_selecionado.exercicios_template:
                novo_ex_reg = ExercicioRegistrado(id_treino=novo_treino_obj.id, id_exercicio=template_ex.id_exercicio); db.session.add(novo_ex_reg)
            flash(f'Treino iniciado com modelo "{template_selecionado.nome}".', 'info')
        else: flash(f'Modelo não encontrado ou não pertence a você.', 'error')
    db.session.commit()
    return redirect(url_for('ver_treino', treino_id=novo_treino_obj.id))

@app.route("/treino/<int:treino_id>")
@login_required
def ver_treino(treino_id):
    treino_atual = Treino.query.get_or_404(treino_id);
    if treino_atual.id_usuario != current_user.id: abort(403)
    todos_exercicios_biblioteca = Exercicio.query.filter_by(id_usuario=current_user.id).all() 
    return render_template("treino.html", treino=treino_atual, biblioteca=todos_exercicios_biblioteca)

@app.route("/treino/<int:treino_id>/add_exercicio_reg", methods=["POST"])
@login_required
def add_exercicio_reg(treino_id):
    treino = Treino.query.get_or_404(treino_id)
    if treino.id_usuario != current_user.id: abort(403)
    exercicio_id = request.form.get("exercicio_id")
    exercicio_existente = ExercicioRegistrado.query.filter_by(id_treino=treino_id, id_exercicio=exercicio_id).first()
    if not exercicio_existente: novo_exercicio_registrado = ExercicioRegistrado(id_treino=treino_id, id_exercicio=exercicio_id); db.session.add(novo_exercicio_registrado); db.session.commit()
    return redirect(url_for("ver_treino", treino_id=treino_id))

@app.route('/exercicio_reg/<int:ex_reg_id>/add_serie', methods=['POST'])
@login_required
def add_serie(ex_reg_id):
    exercicio_registrado = ExercicioRegistrado.query.get_or_404(ex_reg_id)
    if exercicio_registrado.treino.id_usuario != current_user.id: abort(403)
    repeticoes_str=request.form.get('repeticoes'); peso_kg_str=request.form.get('peso_kg'); treino_id = exercicio_registrado.treino.id
    try:
        repeticoes=int(repeticoes_str); peso_kg=float(peso_kg_str)
        if repeticoes<1 or repeticoes>99 or peso_kg<0 or peso_kg>999: raise ValueError("Fora do limite")
    except (ValueError, TypeError): flash('Erro: Reps 1-99, Peso 0-999.', 'error'); return redirect(url_for('ver_treino', treino_id=treino_id))
    numero_da_nova_serie=len(exercicio_registrado.series)+1; nova_serie=Serie(id_exercicio_registrado=ex_reg_id, numero_serie=numero_da_nova_serie, repeticoes=repeticoes, peso_kg=peso_kg); db.session.add(nova_serie); db.session.commit()
    return redirect(url_for('ver_treino', treino_id=treino_id))

@app.route('/serie/<int:serie_id>/delete', methods=['POST'])
@login_required
def delete_serie(serie_id):
    serie_para_excluir = Serie.query.get_or_404(serie_id)
    if serie_para_excluir.exercicio_registrado.treino.id_usuario != current_user.id: abort(403)
    treino_id=serie_para_excluir.exercicio_registrado.treino.id; db.session.delete(serie_para_excluir); db.session.commit()
    return redirect(url_for('ver_treino', treino_id=treino_id))

@app.route('/serie/<int:serie_id>/edit', methods=['GET'])
@login_required
def edit_serie_page(serie_id):
    serie_para_editar = Serie.query.get_or_404(serie_id)
    if serie_para_editar.exercicio_registrado.treino.id_usuario != current_user.id: abort(403)
    return render_template('edit_serie.html', serie=serie_para_editar)

@app.route('/serie/<int:serie_id>/update', methods=['POST'])
@login_required
def update_serie(serie_id):
    serie_para_atualizar = Serie.query.get_or_404(serie_id)
    if serie_para_atualizar.exercicio_registrado.treino.id_usuario != current_user.id: abort(403)
    novas_repeticoes_str=request.form.get('repeticoes'); novo_peso_kg_str=request.form.get('peso_kg'); treino_id = serie_para_atualizar.exercicio_registrado.treino.id
    try:
        novas_repeticoes=int(novas_repeticoes_str); novo_peso_kg=float(novo_peso_kg_str)
        if novas_repeticoes<1 or novas_repeticoes>99 or novo_peso_kg<0 or novo_peso_kg>999: raise ValueError("Fora do limite")
    except (ValueError, TypeError): flash('Erro: Reps 1-99, Peso 0-999.', 'error'); return redirect(url_for('edit_serie_page', serie_id=serie_id))
    serie_para_atualizar.repeticoes=novas_repeticoes; serie_para_atualizar.peso_kg=novo_peso_kg; db.session.commit(); flash(f'Série #{serie_para_atualizar.numero_serie} atualizada!', 'success')
    return redirect(url_for('ver_treino', treino_id=treino_id))

@app.route("/exercicio_reg/<int:ex_reg_id>/delete", methods=["POST"])
@login_required
def delete_exercicio_reg(ex_reg_id):
    ex_reg_para_excluir = ExercicioRegistrado.query.get_or_404(ex_reg_id)
    if ex_reg_para_excluir.treino.id_usuario != current_user.id: abort(403)
    treino_id=ex_reg_para_excluir.treino.id
    for serie in ex_reg_para_excluir.series: db.session.delete(serie)
    db.session.delete(ex_reg_para_excluir); db.session.commit()
    return redirect(url_for('ver_treino', treino_id=treino_id))

@app.route('/exercicio_reg/<int:ex_reg_id>/update_obs', methods=['POST'])
@login_required
def update_observacao(ex_reg_id):
    ex_reg = ExercicioRegistrado.query.get_or_404(ex_reg_id)
    if ex_reg.treino.id_usuario != current_user.id: abort(403)
    nova_observacao = request.form.get('observacoes'); ex_reg.observacoes = nova_observacao; db.session.commit()
    flash('Observação salva com sucesso!', 'success')
    return redirect(url_for('ver_treino', treino_id=ex_reg.treino.id))

@app.route('/treino/<int:treino_id>/finalizar', methods=['POST'])
@login_required
def finalizar_treino(treino_id):
    treino_para_finalizar = Treino.query.get_or_404(treino_id)
    if treino_para_finalizar.id_usuario != current_user.id: abort(403)
    if treino_para_finalizar.hora_fim is None: treino_para_finalizar.hora_fim=datetime.utcnow(); db.session.commit(); flash(f'Treino #{treino_id} finalizado!', 'success')
    else: flash(f'Treino #{treino_id} já finalizado.', 'info')
    return redirect(url_for('sumario_treino', treino_id=treino_id))

@app.route('/treino/<int:treino_id>/sumario')
@login_required
def sumario_treino(treino_id):
    treino = Treino.query.options(joinedload(Treino.exercicios_registrados).joinedload(ExercicioRegistrado.series), joinedload(Treino.exercicios_registrados).joinedload(ExercicioRegistrado.exercicio)).get_or_404(treino_id)
    if treino.id_usuario != current_user.id: abort(403)
    duracao_total_str = "N/A"; volume_total = 0; total_series = 0; total_repeticoes = 0
    if treino.hora_inicio and treino.hora_fim:
        duracao = treino.hora_fim - treino.hora_inicio; total_minutos = int(duracao.total_seconds() // 60)
        if total_minutos < 1: total_segundos = int(duracao.total_seconds() % 60); duracao_total_str = f"{total_segundos} segundos"
        else: duracao_total_str = f"{total_minutos} minutos"
    for ex_reg in treino.exercicios_registrados:
        total_series += len(ex_reg.series)
        for serie in ex_reg.series:
            if serie.peso_kg is not None and serie.repeticoes is not None: volume_total += (serie.peso_kg * serie.repeticoes)
            if serie.repeticoes is not None: total_repeticoes += serie.repeticoes
    return render_template('sumario_treino.html', treino=treino, duracao=duracao_total_str, volume=volume_total, series=total_series, repeticoes=total_repeticoes)

@app.route('/treino/<int:treino_id>/delete', methods=['POST'])
@login_required
def delete_treino(treino_id):
    treino_para_excluir = Treino.query.get_or_404(treino_id)
    if treino_para_excluir.id_usuario != current_user.id:
        abort(403) # <<< CORRIGIDO: Erro de digitação 4403
    try:
        for ex_reg in treino_para_excluir.exercicios_registrados:
            for serie in ex_reg.series: db.session.delete(serie)
            db.session.delete(ex_reg)
        db.session.delete(treino_para_excluir); db.session.commit(); flash(f'Treino #{treino_id} excluído!', 'success')
    except Exception as e: db.session.rollback(); flash(f'Erro: {e}', 'error')
    return redirect(url_for('index'))

@app.route('/treino/<int:treino_id>/copy', methods=['POST'])
@login_required
def copy_treino(treino_id):
    # <<< CORRIGIDO: ... substituído pelo código de joinedload >>>
    treino_original = Treino.query.options(
        joinedload(Treino.exercicios_registrados).joinedload(ExercicioRegistrado.series)
    ).get_or_404(treino_id)
    
    if treino_original.id_usuario != current_user.id:
        abort(403)
        
    novo_treino = Treino(id_usuario=current_user.id, hora_inicio=datetime.utcnow())
    db.session.add(novo_treino)
    db.session.flush()
    try:
        for ex_reg_original in treino_original.exercicios_registrados:
            novo_ex_reg = ExercicioRegistrado(
                id_treino=novo_treino.id, # <<< CORRIGIDO: novo_ino -> novo_treino.id >>>
                id_exercicio=ex_reg_original.id_exercicio, 
                observacoes=ex_reg_original.observacoes
            )
            db.session.add(novo_ex_reg)
            db.session.flush()
            for serie_original in ex_reg_original.series:
                nova_serie = Serie(
                    id_exercicio_registrado=novo_ex_reg.id, 
                    numero_serie=serie_original.numero_serie, 
                    repeticoes=serie_original.repeticoes, 
                    peso_kg=serie_original.peso_kg
                )
                db.session.add(nova_serie)
        db.session.commit()
        flash(f'Treino #{treino_original.id} copiado para o novo Treino #{novo_treino.id}!', 'success')
        return redirect(url_for('ver_treino', treino_id=novo_treino.id))
    except Exception as e:
        db.session.rollback()
        flash(f'Erro ao copiar o treino: {e}', 'error')
        return redirect(url_for('index'))

# --- Rotas de Modelos de Treino (User-Specific) ---
@app.route('/templates', methods=['GET', 'POST'])
@login_required
def gerenciar_templates():
    if request.method == 'POST':
        nome_template = request.form.get('nome_template')
        if not nome_template:
            flash('Erro: O nome do modelo é obrigatório.', 'error')
            return redirect(url_for('gerenciar_templates'))
        
        # <<< CORRIGIDO: Filtra por usuário >>>
        template_existente = TreinoTemplate.query.filter_by(
            nome=nome_template, 
            id_usuario=current_user.id
        ).first()
        
        if template_existente:
            flash(f'Erro: Um modelo com o nome "{nome_template}" já existe.', 'error')
        else:
            # <<< CORRIGIDO: Salva com id_usuario >>>
            novo_template = TreinoTemplate(nome=nome_template, id_usuario=current_user.id)
            db.session.add(novo_template)
            db.session.commit()
            flash(f'Modelo "{nome_template}" criado com sucesso!', 'success')
        return redirect(url_for('gerenciar_templates'))
        
    templates = TreinoTemplate.query.filter_by(id_usuario=current_user.id).order_by(TreinoTemplate.nome).all()
    return render_template('templates.html', templates=templates)

@app.route('/template/<int:template_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_template_page(template_id):
    template = TreinoTemplate.query.get_or_404(template_id)
    if template.id_usuario != current_user.id:
        abort(403)
        
    if request.method == 'POST':
        exercicio_id = request.form.get('exercicio_id')
        if not exercicio_id:
            flash('Erro: Selecione um exercício.', 'error')
            return redirect(url_for('edit_template_page', template_id=template_id))
            
        exercicio_existente = TemplateExercicio.query.filter_by(id_template=template_id, id_exercicio=exercicio_id).first()
        if exercicio_existente:
            flash('Exercício já está no modelo.', 'info')
        else:
            novo_template_ex = TemplateExercicio(id_template=template_id, id_exercicio=exercicio_id)
            db.session.add(novo_template_ex)
            db.session.commit()
            flash('Exercício adicionado!', 'success')
        return redirect(url_for('edit_template_page', template_id=template_id))
        
    biblioteca_exercicios = Exercicio.query.filter_by(id_usuario=current_user.id).order_by(Exercicio.nome).all()
    return render_template('edit_template.html', template=template, biblioteca=biblioteca_exercicios)

@app.route('/template_exercicio/<int:te_id>/delete', methods=['POST'])
@login_required
def delete_template_exercicio(te_id):
    ex_para_remover = TemplateExercicio.query.get_or_404(te_id)
    template_id = ex_para_remover.id_template
    if ex_para_remover.template.id_usuario != current_user.id:
        abort(403)
    try:
        db.session.delete(ex_para_remover)
        db.session.commit()
        flash('Exercício removido do modelo.', 'success')
    # <<< CORRIGIDO: Função estava incompleta >>>
    except Exception as e:
        db.session.rollback()
        flash(f'Erro ao remover exercício: {e}', 'error')
    return redirect(url_for('edit_template_page', template_id=template_id))

@app.route('/template/<int:template_id>/delete', methods=['POST'])
@login_required
def delete_template(template_id):
    template_para_excluir = TreinoTemplate.query.get_or_404(template_id)
    if template_para_excluir.id_usuario != current_user.id:
        abort(403)
    try:
        db.session.delete(template_para_excluir)
        # <<< CORRIGIDO: Função estava incompleta >>>
        db.session.commit()
        flash(f'Modelo "{template_para_excluir.nome}" excluído com sucesso.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Erro ao excluir o modelo: {e}', 'error')
    return redirect(url_for('gerenciar_templates'))

# --- Execução da Aplicação ---
if __name__ == "__main__":
    app.run(host='0.0.0.0', debug=True)